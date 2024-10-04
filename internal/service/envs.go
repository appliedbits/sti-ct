package service

import (
	"os"
	"strconv"
	"time"
)

func GetEnv(key string, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}

func GetEnvAsInt64(key string, defaultValue int64) int64 {
	valueStr := GetEnv(key, "")
	if value, err := strconv.ParseInt(valueStr, 10, 64); err == nil {
		return value
	}
	return defaultValue
}

func GetEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := GetEnv(key, "")
	if value, err := time.ParseDuration(valueStr); err == nil {
		return value
	}
	return defaultValue
}