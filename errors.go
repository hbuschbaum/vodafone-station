package vodafone

type NotLoggedInError struct{}

func (e *NotLoggedInError) Error() string {
	return "not logged in"
}
