package kms

//var ErrRequest = fmt.Errorf("%w TagException", ErrValidation)
//
//type Error struct {
//	Msg string
//	Err error
//}
//
//func (e *Error) Error() string {
//	return e.Msg
//}
//
//func NewError(format string, args ...any) error {
//	return &Error{
//		Msg: fmt.Sprintf(format, args...),
//	}
//}
//
//func NewWrappedError(err error) error {
//	return &Error{
//		Msg: fmt.Sprintf("wrapped error (%s)", err.Error()),
//		Err: err,
//	}
//}
//
//func (e *Error) Unwrap() error {
//	return e.Err
//}
