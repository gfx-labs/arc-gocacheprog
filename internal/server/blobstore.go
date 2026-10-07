package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// BlobStore stores large content-addressed blobs in S3. Object keys are
// <prefix><hex[0:2]>/<hex[2:4]>/<full hex hash> so no single prefix grows
// past 65536 shards worth of fanout.
type BlobStore struct {
	client *s3.Client
	bucket string
	prefix string
}

func NewS3Client(ctx context.Context, c S3Config) (*s3.Client, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(c.Region)}
	if c.AccessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, "")))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	pathStyle := c.Endpoint != ""
	if c.UsePathStyle != nil {
		pathStyle = *c.UsePathStyle
	}
	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
		o.UsePathStyle = pathStyle
		// SeaweedFS and other S3 implementations do not all support the
		// streaming trailer checksums the SDK sends by default.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	}), nil
}

func NewBlobStore(client *s3.Client, bucket, prefix string) *BlobStore {
	return &BlobStore{client: client, bucket: bucket, prefix: prefix}
}

// Key returns the object key for a BLAKE3 hash.
func (b *BlobStore) Key(hash []byte) string {
	h := hex.EncodeToString(hash)
	return b.prefix + h[0:2] + "/" + h[2:4] + "/" + h
}

// HashFromKey parses a key produced by Key. ok is false for foreign objects.
func (b *BlobStore) HashFromKey(key string) ([]byte, bool) {
	rest, found := strings.CutPrefix(key, b.prefix)
	if !found {
		return nil, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return nil, false
	}
	h, err := hex.DecodeString(parts[2])
	if err != nil || len(h) != 32 || parts[0] != parts[2][0:2] || parts[1] != parts[2][2:4] {
		return nil, false
	}
	return h, true
}

func (b *BlobStore) EnsureBucket(ctx context.Context) error {
	_, err := b.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(b.bucket)})
	if err == nil {
		return nil
	}
	var owned *types.BucketAlreadyOwnedByYou
	var exists *types.BucketAlreadyExists
	if errors.As(err, &owned) || errors.As(err, &exists) {
		return nil
	}
	// Some implementations return a generic error for an existing bucket.
	if _, herr := b.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(b.bucket), MaxKeys: aws.Int32(1)}); herr == nil {
		return nil
	}
	return fmt.Errorf("create bucket %s: %w", b.bucket, err)
}

// Put uploads a file. The file must be positioned anywhere; it is rewound.
func (b *BlobStore) Put(ctx context.Context, hash []byte, f *os.File, size int64) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(b.bucket),
		Key:           aws.String(b.Key(hash)),
		Body:          f,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String("application/octet-stream"),
	})
	if err != nil {
		return fmt.Errorf("s3 put %x: %w", hash, err)
	}
	return nil
}

// ErrBlobMissing is returned when the object does not exist in S3.
var ErrBlobMissing = errors.New("blob missing from object store")

func (b *BlobStore) Get(ctx context.Context, hash []byte) (io.ReadCloser, error) {
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(b.Key(hash)),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		var nf *types.NotFound
		if errors.As(err, &nsk) || errors.As(err, &nf) {
			return nil, ErrBlobMissing
		}
		return nil, fmt.Errorf("s3 get %x: %w", hash, err)
	}
	return out.Body, nil
}

func (b *BlobStore) Delete(ctx context.Context, hash []byte) error {
	_, err := b.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(b.Key(hash)),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		var nf *types.NotFound
		if errors.As(err, &nsk) || errors.As(err, &nf) {
			return nil
		}
		return fmt.Errorf("s3 delete %x: %w", hash, err)
	}
	return nil
}

// ObjectInfo is a listed object.
type ObjectInfo struct {
	Key          string
	LastModified time.Time
}

// List calls fn for every object under the prefix.
func (b *BlobStore) List(ctx context.Context, fn func([]ObjectInfo) error) error {
	p := s3.NewListObjectsV2Paginator(b.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(b.bucket),
		Prefix: aws.String(b.prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("s3 list: %w", err)
		}
		batch := make([]ObjectInfo, 0, len(page.Contents))
		for _, o := range page.Contents {
			info := ObjectInfo{Key: aws.ToString(o.Key)}
			if o.LastModified != nil {
				info.LastModified = *o.LastModified
			}
			batch = append(batch, info)
		}
		if err := fn(batch); err != nil {
			return err
		}
	}
	return nil
}
