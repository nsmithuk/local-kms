package kmserr

import (
	"fmt"
)

type ErrType string

const (
	TypeValidation ErrType = "Validation"
)

//---

type ErrCause string

const (
	CauseValidationError               ErrCause = "ValidationError"
	CauseKMSInvalidStateException      ErrCause = "KMSInvalidStateException"
	CauseAlreadyExistsException        ErrCause = "AlreadyExistsException"
	CauseNotFoundException             ErrCause = "NotFoundException"
	CauseTagException                  ErrCause = "TagException"
	CauseLimitExceededException        ErrCause = "LimitExceededException"
	CauseUnsupportedOperationException ErrCause = "UnsupportedOperationException"
	CauseInvalidAliasNameException     ErrCause = "InvalidAliasNameException"
	CauseInvalidImportTokenException   ErrCause = "InvalidImportTokenException"
	CauseIncorrectKeyMaterialException ErrCause = "IncorrectKeyMaterialException"
)

//---

type KMSError struct {
	Type    ErrType
	Cause   ErrCause
	Message error
}

func (e KMSError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Type, e.Cause, e.Message)
}

func New(t ErrType, c ErrCause, format string, args ...any) error {
	return &KMSError{
		Type:    t,
		Cause:   c,
		Message: fmt.Errorf(format, args...),
	}
}

func NewValidation(c ErrCause, format string, args ...any) error {
	return New(TypeValidation, c, format, args...)
}
