//go:build !linux

package main

func dropPrivileges() (bool, int, int, error) { return false, 0, 0, nil }

func raiseBindCapability() bool { return false }
