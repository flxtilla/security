package principal

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func Test_Union(t *testing.T) {
	s := NewSet("1", "2", "3")
	r := NewSet("3", "4", "5")
	x := NewSet("5", "6", "7")

	u := Union(s, r, x)
	if settype := reflect.TypeOf(u).String(); settype != "*principal.set" {
		t.Error("Union should derive its set type from the first passed set, got", settype)
	}
	if u.Size() != 7 {
		t.Error("Union: the merged set doesn't have all items in it.")
	}

	if !u.Has("1", "2", "3", "4", "5", "6", "7") {
		t.Error("Union: merged items are not availabile in the set.")
	}

	z := Union(x, r)
	if z.Size() != 5 {
		t.Error("Union: Union of 2 sets doesn't have the proper number of items.")
	}
	if settype := reflect.TypeOf(z).String(); settype != "*principal.set" {
		t.Error("Union should derive its set type from the first passed set, got", settype)
	}

}

func Test_Difference(t *testing.T) {
	s := NewSet("1", "2", "3")
	r := NewSet("3", "4", "5")
	x := NewSet("5", "6", "7")
	u := Difference(s, r, x)

	if u.Size() != 2 {
		t.Error("Difference: the set doesn't have all items in it.")
	}

	if !u.Has("1", "2") {
		t.Error("Difference: items are not availabile in the set.")
	}

	y := Difference(r, r)
	if y.Size() != 0 {
		t.Error("Difference: size should be zero")
	}

}

func Test_Intersection(t *testing.T) {
	s1 := NewSet("1", "3", "4", "5")
	s2 := NewSet("2", "3", "5", "6")
	s3 := NewSet("4", "5", "6", "7")
	u := Intersection(s1, s2, s3)

	if u.Size() != 1 {
		t.Error("Intersection: the set doesn't have all items in it.")
	}

	if !u.Has("5") {
		t.Error("Intersection: items after intersection are not availabile in the set.")
	}
}

func Test_SymmetricDifference(t *testing.T) {
	s := NewSet("1", "2", "3")
	r := NewSet("3", "4", "5")
	u := SymmetricDifference(s, r)

	if u.Size() != 4 {
		t.Error("SymmetricDifference: the set doesn't have all items in it.")
	}

	if !u.Has("1", "2", "4", "5") {
		t.Error("SymmetricDifference: items are not availabile in the set.")
	}
}

func Test_StringSlice(t *testing.T) {
	s := NewSet("san francisco", "istanbul", 3.14, 1321, "ankara")
	u := StringSlice(s)

	if len(u) != 3 {
		t.Error("StringSlice: slice should only have three items")
	}

	for _, item := range u {
		r := reflect.TypeOf(item)
		if r.Kind().String() != "string" {
			t.Error("StringSlice: slice item should be a string")
		}
	}
}

func Test_IntSlice(t *testing.T) {
	s := NewSet("san francisco", "istanbul", 3.14, 1321, "ankara", 8876)
	u := IntSlice(s)

	if len(u) != 2 {
		t.Error("IntSlice: slice should only have two items")
	}

	for _, item := range u {
		r := reflect.TypeOf(item)
		if r.Kind().String() != "int" {
			t.Error("Intslice: slice item should be a int")
		}
	}
}

func TestSet_NewSet(t *testing.T) {
	s := NewSet()

	if s.Size() != 0 {
		t.Error("New: calling without any parameters should create a set with zero size")
	}

	u := s.New()
	if u.Size() != 0 {
		t.Error("New: creating a new set via s.NewSet() should create a set with zero size")
	}
}

func TestSet_New_parameters(t *testing.T) {
	s := NewSet("string", "another_string", 1, 3.14)

	if s.Size() != 4 {
		t.Error("New: calling with parameters should create a set with size of four")
	}
}

func TestSet_Add(t *testing.T) {
	s := NewSet()
	s.Add(1)
	s.Add(2)
	s.Add(2) // duplicate
	s.Add("fatih")
	s.Add("zeynep")
	s.Add("zeynep") // another duplicate

	if s.Size() != 4 {
		t.Error("Add: items are not unique. The set size should be four")
	}

	if !s.Has(1, 2, "fatih", "zeynep") {
		t.Error("Add: added items are not availabile in the set.")
	}
}

func TestSet_Add_multiple(t *testing.T) {
	s := NewSet()
	s.Add("ankara", "san francisco", 3.14)

	if s.Size() != 3 {
		t.Error("Add: items are not unique. The set size should be three")
	}

	if !s.Has("ankara", "san francisco", 3.14) {
		t.Error("Add: added items are not availabile in the set.")
	}
}

func TestSet_Remove(t *testing.T) {
	s := NewSet()
	s.Add(1)
	s.Add(2)
	s.Add("fatih")

	s.Remove(1)
	if s.Size() != 2 {
		t.Error("Remove: set size should be two after removing")
	}

	s.Remove(1)
	if s.Size() != 2 {
		t.Error("Remove: set size should be not change after trying to remove a non-existing item")
	}

	s.Remove(2)
	s.Remove("fatih")
	if s.Size() != 0 {
		t.Error("Remove: set size should be zero")
	}

	s.Remove("fatih") // try to remove something from a zero length set
}

func TestSet_Remove_multiple(t *testing.T) {
	s := NewSet()
	s.Add("ankara", "san francisco", 3.14, "istanbul")
	s.Remove("ankara", "san francisco", 3.14)

	if s.Size() != 1 {
		t.Error("Remove: items are not unique. The set size should be four")
	}

	if !s.Has("istanbul") {
		t.Error("Add: added items are not availabile in the set.")
	}
}

func TestSet_Pop(t *testing.T) {
	s := NewSet()
	s.Add(1)
	s.Add(2)
	s.Add("fatih")

	a := s.Pop()
	if s.Size() != 2 {
		t.Error("Pop: set size should be two after popping out")
	}

	if s.Has(a) {
		t.Error("Pop: returned item should not exist")
	}

	s.Pop()
	s.Pop()
	b := s.Pop()
	if b != nil {
		t.Error("Pop: should return nil because set is empty")
	}

	s.Pop() // try to remove something from a zero length set
}

func TestSet_Has(t *testing.T) {
	s := NewSet("1", "2", "3", "4")

	if !s.Has("1") {
		t.Error("Has: the item 1 exist, but 'Has' is returning false")
	}

	if !s.Has("1", "2", "3", "4") {
		t.Error("Has: the items all exist, but 'Has' is returning false")
	}
}

func TestSet_Clear(t *testing.T) {
	s := NewSet()
	s.Add(1)
	s.Add("istanbul")
	s.Add("san francisco")

	s.Clear()
	if s.Size() != 0 {
		t.Error("Clear: set size should be zero")
	}
}

func TestSet_IsEmpty(t *testing.T) {
	s := NewSet()

	empty := s.IsEmpty()
	if !empty {
		t.Error("IsEmpty: set is empty, it should be true")
	}

	s.Add(2)
	s.Add(3)
	notEmpty := s.IsEmpty()

	if notEmpty {
		t.Error("IsEmpty: set is filled, it should be false")
	}
}

func TestSet_IsEqual(t *testing.T) {
	s := NewSet("1", "2", "3")
	u := NewSet("1", "2", "3")

	ok := s.IsEqual(u)
	if !ok {
		t.Error("IsEqual: set s and t are equal. However it returns false")
	}

	// same size, different content
	a := NewSet("1", "2", "3")
	b := NewSet("4", "5", "6")

	ok = a.IsEqual(b)
	if ok {
		t.Error("IsEqual: set a and b are now equal (1). However it returns true")
	}

	// different size, similar content
	a = NewSet("1", "2", "3")
	b = NewSet("1", "2", "3", "4")

	ok = a.IsEqual(b)
	if ok {
		t.Error("IsEqual: set s and t are now equal (2). However it returns true")
	}

}

func TestSet_IsSubset(t *testing.T) {
	s := NewSet("1", "2", "3", "4")
	u := NewSet("1", "2", "3")

	ok := s.IsSubset(u)
	if !ok {
		t.Error("IsSubset: u is a subset of s. However it returns false")
	}

	ok = u.IsSubset(s)
	if ok {
		t.Error("IsSubset: s is not a subset of u. However it returns true")
	}

}

func TestSet_IsSuperset(t *testing.T) {
	s := NewSet("1", "2", "3", "4")
	u := NewSet("1", "2", "3")

	ok := u.IsSuperset(s)
	if !ok {
		t.Error("IsSuperset: s is a superset of u. However it returns false")
	}

	ok = s.IsSuperset(u)
	if ok {
		t.Error("IsSuperset: u is not a superset of u. However it returns true")
	}

}

func TestSet_String(t *testing.T) {
	s := NewSet()
	if s.String() != "[]" {
		t.Errorf("String: output is not what is excepted '%s'", s.String())
	}

	s.Add("1", "2", "3", "4")
	if !strings.HasPrefix(s.String(), "[") {
		t.Error("String: output should begin with a square bracket")
	}

	if !strings.HasSuffix(s.String(), "]") {
		t.Error("String: output should end with a square bracket")
	}
}

func TestSet_List(t *testing.T) {
	s := NewSet("1", "2", "3", "4")

	// this returns a slice of interface{}
	if len(s.List()) != 4 {
		t.Error("List: slice size should be four.")
	}

	for _, item := range s.List() {
		r := reflect.TypeOf(item)
		if r.Kind().String() != "string" {
			t.Error("List: slice item should be a string")
		}
	}
}

func TestSet_Copy(t *testing.T) {
	s := NewSet("1", "2", "3", "4")
	r := s.Copy()

	if !s.IsEqual(r) {
		t.Error("Copy: set s and r are not equal")
	}
}

func TestSet_Merge(t *testing.T) {
	s := NewSet("1", "2", "3")
	r := NewSet("3", "4", "5")
	s.Merge(r)

	if s.Size() != 5 {
		t.Error("Merge: the set doesn't have all items in it.")
	}

	if !s.Has("1", "2", "3", "4", "5") {
		t.Error("Merge: merged items are not availabile in the set.")
	}
}

func TestSet_Separate(t *testing.T) {
	s := NewSet("1", "2", "3")
	r := NewSet("3", "5")
	s.Separate(r)

	if s.Size() != 2 {
		t.Error("Separate: the set doesn't have all items in it.")
	}

	if !s.Has("1", "2") {
		t.Error("Separate: items after separation are not availabile in the set.")
	}
}

func TestSet_RaceAdd(t *testing.T) {
	// Create two sets. Add concurrently items to each of them. Remove from the
	// other one.
	// "go test -race" should detect this if the library is not thread-safe.
	s := NewSet()
	u := NewSet()

	go func() {
		for i := 0; i < 1000; i++ {
			item := "item" + strconv.Itoa(i)
			go func(i int) {
				s.Add(item)
				u.Add(item)
			}(i)
		}
	}()

	for i := 0; i < 1000; i++ {
		item := "item" + strconv.Itoa(i)
		go func(i int) {
			s.Add(item)
			u.Add(item)
		}(i)
	}
}
