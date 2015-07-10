// A local implementation of gopkg.in/fatih/set.v0
package principal

import (
	"fmt"
	"strings"
	"sync"
)

// Describing a Set: an unordered, unique list of values.
type Set interface {
	New(...interface{}) Set
	Add(...interface{})
	Remove(...interface{})
	Pop() interface{}
	Has(...interface{}) bool
	Size() int
	Clear()
	IsEmpty() bool
	IsEqual(Set) bool
	IsSubset(Set) bool
	IsSuperset(Set) bool
	Each(func(interface{}) bool)
	String() string
	List() []interface{}
	Copy() Set
	Merge(Set)
	Separate(Set)
}

type set struct {
	M map[interface{}]struct{}
	l sync.RWMutex
}

func NewSet(items ...interface{}) Set {
	s := &set{}
	s.M = make(map[interface{}]struct{})

	s.Add(items...)
	return s
}

func (s *set) New(items ...interface{}) Set {
	return NewSet(items...)
}

func (s *set) Add(items ...interface{}) {
	if len(items) == 0 {
		return
	}

	s.l.Lock()
	defer s.l.Unlock()

	for _, item := range items {
		s.M[item] = keyExists
	}
}

func (s *set) Remove(items ...interface{}) {
	if len(items) == 0 {
		return
	}

	s.l.Lock()
	defer s.l.Unlock()

	for _, item := range items {
		delete(s.M, item)
	}
}

func (s *set) Pop() interface{} {
	s.l.RLock()
	for item := range s.M {
		s.l.RUnlock()
		s.l.Lock()
		delete(s.M, item)
		s.l.Unlock()
		return item
	}
	s.l.RUnlock()
	return nil
}

func (s *set) Has(items ...interface{}) bool {
	if len(items) == 0 {
		return false
	}

	s.l.RLock()
	defer s.l.RUnlock()

	has := true
	for _, item := range items {
		if _, has = s.M[item]; !has {
			break
		}
	}
	return has
}

func (s *set) Size() int {
	s.l.RLock()
	defer s.l.RUnlock()

	l := len(s.M)
	return l
}

func (s *set) Clear() {
	s.l.Lock()
	defer s.l.Unlock()

	s.M = make(map[interface{}]struct{})
}

func (s *set) IsEqual(t Set) bool {
	s.l.RLock()
	defer s.l.RUnlock()

	if conv, ok := t.(*set); ok {
		conv.l.RLock()
		defer conv.l.RUnlock()
	}

	if sameSize := len(s.M) == t.Size(); !sameSize {
		return false
	}

	equal := true
	t.Each(func(item interface{}) bool {
		_, equal = s.M[item]
		return equal // if false, Each() will end
	})

	return equal
}

func (s *set) IsSuperset(t Set) bool {
	return t.IsSubset(s)
}

func (s *set) IsSubset(t Set) (subset bool) {
	s.l.RLock()
	defer s.l.RUnlock()

	subset = true

	t.Each(func(item interface{}) bool {
		_, subset = s.M[item]
		return subset
	})

	return
}

func (s *set) Each(f func(item interface{}) bool) {
	s.l.RLock()
	defer s.l.RUnlock()

	for item := range s.M {
		if !f(item) {
			break
		}
	}
}

func (s *set) List() []interface{} {
	s.l.RLock()
	defer s.l.RUnlock()

	list := make([]interface{}, 0, len(s.M))

	for item := range s.M {
		list = append(list, item)
	}

	return list
}

func (s *set) Copy() Set {
	return NewSet(s.List()...)
}

func (s *set) Merge(t Set) {
	s.l.Lock()
	defer s.l.Unlock()

	t.Each(func(item interface{}) bool {
		s.M[item] = keyExists
		return true
	})
}

func (s *set) Separate(t Set) {
	s.Remove(t.List()...)
}

func (s *set) IsEmpty() bool {
	return s.Size() == 0
}

func (s *set) String() string {
	t := make([]string, 0, len(s.List()))
	for _, item := range s.List() {
		t = append(t, fmt.Sprintf("%v", item))
	}

	return fmt.Sprintf("[%s]", strings.Join(t, ", "))
}

var keyExists = struct{}{}

// Union is the merger of multiple sets. It returns a new set with all the
// elements present in all the sets that are passed.
//
// The dynamic type of the returned set is determined by the first passed set's
// implementation of the New() method.
func Union(set1, set2 Set, sets ...Set) Set {
	u := set1.Copy()
	set2.Each(func(item interface{}) bool {
		u.Add(item)
		return true
	})
	for _, set := range sets {
		set.Each(func(item interface{}) bool {
			u.Add(item)
			return true
		})
	}

	return u
}

// Difference returns a new set which contains items which are in in the first
// set but not in the others. Unlike the Difference() method you can use this
// function separately with multiple sets.
func Difference(set1, set2 Set, sets ...Set) Set {
	s := set1.Copy()
	s.Separate(set2)
	for _, set := range sets {
		s.Separate(set) // seperate is thread safe
	}
	return s
}

// Intersection returns a new set which contains items that only exist in all given sets.
func Intersection(set1, set2 Set, sets ...Set) Set {
	all := Union(set1, set2, sets...)
	result := Union(set1, set2, sets...)

	all.Each(func(item interface{}) bool {
		if !set1.Has(item) || !set2.Has(item) {
			result.Remove(item)
		}

		for _, set := range sets {
			if !set.Has(item) {
				result.Remove(item)
			}
		}
		return true
	})
	return result
}

// SymmetricDifference returns a new set which s is the difference of items which are in
// one of either, but not in both.
func SymmetricDifference(s Set, t Set) Set {
	u := Difference(s, t)
	v := Difference(t, s)
	return Union(u, v)
}

// StringSlice is a helper function that returns a slice of strings of s. If
// the set contains mixed types of items only items of type string are returned.
func StringSlice(s Set) []string {
	slice := make([]string, 0)
	for _, item := range s.List() {
		v, ok := item.(string)
		if !ok {
			continue
		}

		slice = append(slice, v)
	}
	return slice
}

// IntSlice is a helper function that returns a slice of ints of s. If
// the set contains mixed types of items only items of type int are returned.
func IntSlice(s Set) []int {
	slice := make([]int, 0)
	for _, item := range s.List() {
		v, ok := item.(int)
		if !ok {
			continue
		}

		slice = append(slice, v)
	}
	return slice
}
