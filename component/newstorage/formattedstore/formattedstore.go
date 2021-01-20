/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package formattedstore

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/newstorage"
)

const (
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2

	failFormat               = `failed to format %s "%s": %w`
	failFormatTags           = "failed to format tags: %w"
	failDeformat             = `failed to deformat %s "%s" returned from the underlying store: %w`
	failQueryUnderlyingStore = "failed to query underlying store: %w"
)

var errInvalidQueryExpressionFormat = errors.New("invalid expression format. " +
	"it must be in the following format: TagName:TagValue")

// Formatter represents a type that can convert data between two formats.
type Formatter interface {
	FormatKey(key string) (formattedKey string, err error)
	FormatValue(value []byte) (formattedValue []byte, err error)
	FormatTags(tags ...newstorage.Tag) (formattedTags []newstorage.Tag, err error)
	DeformatKey(formattedKey string) (key string, err error)
	DeformatValue(formattedValue []byte) (value []byte, err error)
	DeformatTags(formattedTags ...newstorage.Tag) (tags []newstorage.Tag, err error)
}

// FormattedProvider is a newstorage.Provider that allows for data to be formatted in an underlying provider.
type FormattedProvider struct {
	provider  newstorage.Provider
	formatter Formatter
}

// NewProvider instantiates a new FormattedProvider with the given newstorage.Provider and Formatter.
// The Formatter is used to format data before being sent to the Provider for storage.
// The Formatter is also used to restore the original format of data being retrieved from Provider.
func NewProvider(provider newstorage.Provider, formatter Formatter) *FormattedProvider {
	formattedProvider := &FormattedProvider{
		provider:  provider,
		formatter: formatter,
	}

	return formattedProvider
}

// OpenStore opens a store with the given name and returns a handle.
// If the store has never been opened before, then it is created.
// Store names are not case-sensitive.
func (f *FormattedProvider) OpenStore(name string) (newstorage.Store, error) {
	store, err := f.provider.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open store in underlying provider: %w", err)
	}

	newFormatStore := formatStore{
		store:     store,
		formatter: f.formatter,
	}

	return &newFormatStore, nil
}

// SetStoreConfig sets the configuration on a store.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping newstorage.ErrStoreNotFound will be
// returned from the underlying provider.
func (f *FormattedProvider) SetStoreConfig(name string, config newstorage.StoreConfiguration) error {
	formattedTagNames := make([]string, len(config.TagNames))

	for i, tagName := range config.TagNames {
		formattedTags, err := f.formatter.FormatTags(newstorage.Tag{Name: tagName})
		if err != nil {
			return fmt.Errorf(failFormat, "tag name", tagName, err)
		}

		formattedTagNames[i] = formattedTags[0].Name
	}

	err := f.provider.SetStoreConfig(name, newstorage.StoreConfiguration{TagNames: formattedTagNames})
	if err != nil {
		return fmt.Errorf("failed to set store configuration in underlying provider: %w", err)
	}

	return nil
}

// GetStoreConfig gets the current store configuration.
// The store must be created prior to calling this method.
// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned.
func (f *FormattedProvider) GetStoreConfig(name string) (newstorage.StoreConfiguration, error) {
	formattedConfig, err := f.provider.GetStoreConfig(name)
	if err != nil {
		return newstorage.StoreConfiguration{},
			fmt.Errorf("failed to get formatted configuration from the underlying store: %w", err)
	}

	tagNames := make([]string, len(formattedConfig.TagNames))

	for i, formattedTagName := range formattedConfig.TagNames {
		tags, err := f.formatter.DeformatTags(newstorage.Tag{Name: formattedTagName})
		if err != nil {
			return newstorage.StoreConfiguration{}, fmt.Errorf(failDeformat, "tag name", formattedTagName, err)
		}

		tagNames[i] = tags[0].Name
	}

	return newstorage.StoreConfiguration{TagNames: tagNames}, nil
}

// Close closes all stores created under this store provider.
// For persistent store implementations, this does not delete any data in the underlying stores.
func (f *FormattedProvider) Close() error {
	err := f.provider.Close()
	if err != nil {
		return fmt.Errorf("failed to close underlying provider: %w", err)
	}

	return nil
}

type formatStore struct {
	store     newstorage.Store
	formatter Formatter
}

func (f *formatStore) Put(key string, value []byte, tags ...newstorage.Tag) error {
	if value == nil {
		return errors.New("value cannot be nil")
	}

	formattedKey, err := f.formatter.FormatKey(key)
	if err != nil {
		return fmt.Errorf(failFormat, "key", key, err)
	}

	formattedValue, err := f.formatter.FormatValue(value)
	if err != nil {
		return fmt.Errorf(failFormat, "value", value, err)
	}

	formattedTags, err := f.formatter.FormatTags(tags...)
	if err != nil {
		return fmt.Errorf(failFormatTags, err)
	}

	err = f.store.Put(formattedKey, formattedValue, formattedTags...)
	if err != nil {
		return fmt.Errorf("failed to put formatted data in underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) Get(key string) ([]byte, error) {
	formattedKey, err := f.formatter.FormatKey(key)
	if err != nil {
		return nil, fmt.Errorf(failFormat, "key", key, err)
	}

	formattedValue, err := f.store.Get(formattedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted value from underlying store: %w", err)
	}

	value, err := f.formatter.DeformatValue(formattedValue)
	if err != nil {
		return nil, fmt.Errorf(failDeformat, "value", string(formattedValue), err)
	}

	return value, nil
}

func (f *formatStore) GetTags(key string) ([]newstorage.Tag, error) {
	formattedKey, err := f.formatter.FormatKey(key)
	if err != nil {
		return nil, fmt.Errorf(failFormat, "key", key, err)
	}

	formattedTags, err := f.store.GetTags(formattedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted tags from underlying store: %w", err)
	}

	tags, err := f.formatter.DeformatTags(formattedTags...)
	if err != nil {
		return nil, fmt.Errorf("failed to deformat tags: %w", err)
	}

	return tags, nil
}

func (f *formatStore) GetBulk(keys ...string) ([][]byte, error) {
	formattedKeys := make([]string, len(keys))

	for i, key := range keys {
		var err error
		formattedKeys[i], err = f.formatter.FormatKey(key)

		if err != nil {
			return nil, fmt.Errorf(failFormat, "key", key, err)
		}
	}

	formattedValues, err := f.store.GetBulk(formattedKeys...)
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted values from underlying store: %w", err)
	}

	deformattedValues := make([][]byte, len(formattedValues))

	for i, formattedValue := range formattedValues {
		if formattedValue != nil {
			deformattedValue, err := f.formatter.DeformatValue(formattedValue)
			if err != nil {
				return nil, fmt.Errorf(failDeformat, "value", formattedValue, err)
			}

			deformattedValues[i] = deformattedValue
		}
	}

	return deformattedValues, nil
}

func (f *formatStore) Query(expression string, options ...newstorage.QueryOption) (newstorage.Iterator, error) {
	if expression == "" {
		return &formattedIterator{}, errInvalidQueryExpressionFormat
	}

	expressionSplit := strings.Split(expression, ":")
	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		formattedTags, err := f.formatter.FormatTags(newstorage.Tag{Name: expressionSplit[0]})
		if err != nil {
			return &formattedIterator{}, fmt.Errorf(failFormat, "tag name", expressionSplit[0], err)
		}

		underlyingIterator, err := f.store.Query(formattedTags[0].Name, options...)
		if err != nil {
			return &formattedIterator{}, fmt.Errorf(failQueryUnderlyingStore, err)
		}

		return &formattedIterator{underlyingIterator: underlyingIterator, formatter: f.formatter}, nil
	case expressionTagNameAndValueLength:
		formattedTags, err := f.formatter.FormatTags(
			newstorage.Tag{Name: expressionSplit[0], Value: expressionSplit[1]})
		if err != nil {
			return &formattedIterator{}, fmt.Errorf("failed to format tag: %w", err)
		}

		underlyingIterator, err := f.store.Query(
			fmt.Sprintf("%s:%s", formattedTags[0].Name, formattedTags[0].Value), options...)
		if err != nil {
			return &formattedIterator{}, fmt.Errorf(failQueryUnderlyingStore, err)
		}

		return &formattedIterator{underlyingIterator: underlyingIterator, formatter: f.formatter}, nil
	default:
		return &formattedIterator{}, errInvalidQueryExpressionFormat
	}
}

func (f *formatStore) Delete(key string) error {
	formattedKey, err := f.formatter.FormatKey(key)
	if err != nil {
		return fmt.Errorf(failFormat, "key", key, err)
	}

	err = f.store.Delete(formattedKey)
	if err != nil {
		return fmt.Errorf("failed to delete data in underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) Batch(operations []newstorage.Operation) error {
	formattedOperations := make([]newstorage.Operation, len(operations))

	for i, operation := range operations {
		formattedKey, err := f.formatter.FormatKey(operation.Key)
		if err != nil {
			return fmt.Errorf(failFormat, "key", operation.Key, err)
		}

		var formattedValue []byte
		if operation.Value != nil {
			formattedValue, err = f.formatter.FormatValue(operation.Value)
			if err != nil {
				return fmt.Errorf(failFormat, "value", operation.Value, err)
			}
		}

		formattedTags, err := f.formatter.FormatTags(operation.Tags...)
		if err != nil {
			return fmt.Errorf(failFormatTags, err)
		}

		formattedOperations[i] = newstorage.Operation{
			Key:   formattedKey,
			Value: formattedValue,
			Tags:  formattedTags,
		}
	}

	err := f.store.Batch(formattedOperations)
	if err != nil {
		return fmt.Errorf("failed to perform formatted operations in underlying store: %w", err)
	}

	return nil
}

func (f *formatStore) Close() error {
	err := f.store.Close()
	if err != nil {
		return fmt.Errorf("failed to close underlying store: %w", err)
	}

	return nil
}

type formattedIterator struct {
	underlyingIterator newstorage.Iterator
	formatter          Formatter
}

func (f *formattedIterator) Next() (bool, error) {
	nextOK, err := f.underlyingIterator.Next()
	if err != nil {
		return false, fmt.Errorf("failed to move the entry pointer in the underlying iterator: %w", err)
	}

	return nextOK, nil
}

func (f *formattedIterator) Key() (string, error) {
	formattedKey, err := f.underlyingIterator.Key()
	if err != nil {
		return "", fmt.Errorf("failed to get formatted key from the underlying iterator: %w", err)
	}

	key, err := f.formatter.DeformatKey(formattedKey)
	if err != nil {
		return "", fmt.Errorf("failed to deformat formatted key from the underying iterator: %w", err)
	}

	return key, nil
}

func (f *formattedIterator) Value() ([]byte, error) {
	formattedValue, err := f.underlyingIterator.Value()
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted value from the underlying iterator: %w", err)
	}

	value, err := f.formatter.DeformatValue(formattedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to deformat formatted value from the underying iterator: %w", err)
	}

	return value, nil
}

func (f *formattedIterator) Tags() ([]newstorage.Tag, error) {
	formattedTags, err := f.underlyingIterator.Tags()
	if err != nil {
		return nil, fmt.Errorf("failed to get formatted tags from the underlying iterator: %w", err)
	}

	tags, err := f.formatter.DeformatTags(formattedTags...)
	if err != nil {
		return nil, fmt.Errorf("failed to deformat formatted tags from the underlying iterator: %w", err)
	}

	return tags, nil
}

func (f *formattedIterator) Close() error {
	err := f.underlyingIterator.Close()
	if err != nil {
		return fmt.Errorf("failed to close underlying iterator: %w", err)
	}

	return nil
}
