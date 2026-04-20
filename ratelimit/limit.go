package ratelimit

import (
	"sync"
	"time"
)

type LimitStruct struct {
	m              *sync.Mutex
	nodes          map[string]*bucketNodeStruct
	newestNode     *bucketNodeStruct
	oldestNode     *bucketNodeStruct
	maxItemCount   int
	maxTokenCount  int
	refillInterval time.Duration
}

func NewLimit(maxItemCount int, maxTokenCount int, refillInterval time.Duration) *LimitStruct {
	if maxItemCount < 1 {
		panic("maxItemCount must be greater than 0")
	}
	if maxTokenCount < 1 {
		panic("maxItemCount must be greater than 0")
	}
	if refillInterval <= 0 {
		panic("refillInterval must be positive")
	}
	limit := &LimitStruct{
		m:              &sync.Mutex{},
		nodes:          map[string]*bucketNodeStruct{},
		newestNode:     nil,
		maxItemCount:   maxItemCount,
		maxTokenCount:  maxTokenCount,
		refillInterval: refillInterval,
	}
	return limit
}

func (limit *LimitStruct) Consume(key string) bool {
	now := time.Now()

	limit.m.Lock()
	node, ok := limit.nodes[key]
	if !ok {
		node := &bucketNodeStruct{
			key:            key,
			tokenCount:     limit.maxTokenCount - 1,
			lastRefilledAt: now,
		}

		if len(limit.nodes) == limit.maxItemCount {
			if limit.newestNode == limit.oldestNode {
				delete(limit.nodes, limit.oldestNode.key)
				limit.newestNode = nil
				limit.oldestNode = nil
			} else {
				delete(limit.nodes, limit.oldestNode.key)
				limit.oldestNode.newerNode.olderNode = nil
				limit.oldestNode = limit.oldestNode.newerNode
			}
		}

		if limit.newestNode != nil {
			limit.newestNode.newerNode = node
			node.olderNode = limit.newestNode
		}

		limit.nodes[key] = node
		limit.newestNode = node
		if limit.oldestNode == nil {
			limit.oldestNode = node
		}

		limit.m.Unlock()
		return true
	}

	tokenRefillCount := int(now.Sub(node.lastRefilledAt) / limit.refillInterval)
	node.tokenCount += tokenRefillCount
	if node.tokenCount > limit.maxTokenCount {
		node.tokenCount = limit.maxTokenCount
	}
	node.lastRefilledAt = node.lastRefilledAt.Add(limit.refillInterval * time.Duration(tokenRefillCount))

	if node != limit.newestNode {
		if node == limit.oldestNode {
			node.newerNode.olderNode = nil
			limit.oldestNode = node.newerNode
		} else {
			node.newerNode.olderNode = node.olderNode
			node.olderNode.newerNode = node.newerNode
		}
		node.newerNode = nil
		limit.newestNode.newerNode = node
		node.olderNode = limit.newestNode
		limit.newestNode = node
		if limit.oldestNode == nil {
			limit.oldestNode = node
		}
	}

	if node.tokenCount < 1 {
		limit.m.Unlock()
		return false
	}

	node.tokenCount--

	limit.m.Unlock()
	return true
}

func (limit *LimitStruct) Delete(key string) bool {
	limit.m.Lock()

	node, ok := limit.nodes[key]
	if !ok {
		limit.m.Unlock()
		return false
	}

	if node.newerNode != nil {
		node.newerNode.olderNode = node.olderNode
	}
	if node.olderNode != nil {
		node.olderNode.newerNode = node.newerNode
	}

	delete(limit.nodes, node.key)

	if node == limit.newestNode {
		limit.newestNode = node.olderNode
	}

	if node == limit.oldestNode {
		limit.oldestNode = node.newerNode
	}

	limit.m.Unlock()
	return true
}

func (limit *LimitStruct) Clear() {
	limit.m.Lock()
	limit.nodes = map[string]*bucketNodeStruct{}
	limit.newestNode = nil
	limit.oldestNode = nil
	limit.m.Unlock()
}

type bucketNodeStruct struct {
	newerNode      *bucketNodeStruct
	olderNode      *bucketNodeStruct
	key            string
	tokenCount     int
	lastRefilledAt time.Time
}
