package main

import (
	"strings"
)

func verifyAccountIdentifierEmailAddressPattern(email string) bool {
	if len(email) > 100 {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	localPartAllowed := verifyEmailAddressLocalPart(parts[0])
	if !localPartAllowed {
		return false
	}
	domainPartAllowed := verifyEmailAddressDomainPart(parts[1])
	if !localPartAllowed {
		return false
	}
	return domainPartAllowed
}

func verifyEmailAddressLocalPart(part string) bool {
	if len(part) < 1 {
		return false
	}
	for _, char := range part {
		if char >= 'a' && char <= 'z' {
			continue
		}
		if char >= '0' && char <= '9' {
			continue
		}
		if char == '.' || char == '-' || char == '_' || char == '+' {
			continue
		}
		return false
	}
	return true
}

func verifyEmailAddressDomainPart(part string) bool {
	if len(part) < 1 {
		return false
	}
	periodIncluded := false
	for _, char := range part {
		if char >= 'a' && char <= 'z' {
			continue
		}
		if char >= '0' && char <= '9' {
			continue
		}
		if char == '.' {
			periodIncluded = true
			continue
		}
		if char == '-' || char == '_' {
			continue
		}
		return false
	}
	if !periodIncluded {
		return false
	}
	if part[0] == '.' || part[len(part)-1] == '.' {
		return false
	}
	return true
}
