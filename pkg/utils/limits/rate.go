package limits

func RateLimitWithProxy(rateLimit int) int {
	return rateLimit / 2
}

func InArray[T comparable](item T, arrayData []T) bool {
	dataLen := len(arrayData)
	if dataLen == 0 {
		return false
	}
	for i := 0; i < dataLen; i++ {
		if item == arrayData[i] {
			return true
		}
	}
	return false
}
