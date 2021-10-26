package oidc

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

func getCtyValueWithImpliedType(a interface{}) (cty.Value, error) {
	if a == nil {
		return cty.NilVal, fmt.Errorf("input is nil")
	}

	valueType, err := gocty.ImpliedType(a)
	if err != nil {
		return cty.NilVal, fmt.Errorf("unable to get cty.Type: %w", err)
	}

	return getCtyValueWithType(a, valueType)
}

func getCtyValueWithType(a interface{}, vt cty.Type) (cty.Value, error) {
	if a == nil {
		return cty.NilVal, fmt.Errorf("input value is nil")
	}

	if vt == cty.NilType {
		return cty.NilVal, fmt.Errorf("input type is nil")
	}

	value, err := gocty.ToCtyValue(a, vt)
	if err != nil {
		// we should never receive this error
		return cty.NilVal, fmt.Errorf("unable to get cty.Value: %w", err)
	}

	return value, nil
}

func getCtyValues(a interface{}, b interface{}) (cty.Value, cty.Value, error) {
	first, err := getCtyValueWithImpliedType(a)
	if err != nil {
		return cty.NilVal, cty.NilVal, err
	}

	second, err := getCtyValueWithType(b, first.Type())
	if err != nil {
		return cty.NilVal, cty.NilVal, err
	}

	return first, second, nil
}

func isCtyPrimitiveValueValid(a cty.Value, b cty.Value) bool {
	if !isCtyTypeSame(a, b) {
		return false
	}

	if getCtyType(a) != primitiveCtyType {
		return false
	}

	return a.Equals(b) == cty.True
}

func isCtyListValid(a cty.Value, b cty.Value) bool {
	if !isCtyTypeSame(a, b) {
		return false
	}

	if getCtyType(a) != listCtyType {
		return false
	}

	listA := a.AsValueSlice()
	listB := b.AsValueSlice()

	for i := range listA {
		if !ctyListContains(listB, listA[i]) {
			return false
		}
	}

	return true
}

func isCtyMapValid(a cty.Value, b cty.Value) bool {
	if !isCtyTypeSame(a, b) {
		return false
	}

	if getCtyType(a) != mapCtyType {
		return false
	}

	mapA := a.AsValueMap()
	mapB := b.AsValueMap()

	for k := range mapA {
		mapBValue, ok := mapB[k]
		if !ok {
			return false
		}

		err := isCtyValueValid(mapA[k], mapBValue)
		if err != nil {
			return false
		}
	}

	return true
}

func ctyListContains(a []cty.Value, b cty.Value) bool {
	for i := range a {
		err := isCtyValueValid(a[i], b)
		if err == nil {
			return true
		}
	}

	return false
}

func isCtyTypeSame(a cty.Value, b cty.Value) bool {
	return a.Type().Equals(b.Type())
}

func isCtyValueValid(a cty.Value, b cty.Value) error {
	if !isCtyTypeSame(a, b) {
		return fmt.Errorf("should be type %s, was type: %s", a.Type().GoString(), b.Type().GoString())
	}

	switch getCtyType(a) {
	case primitiveCtyType:
		valid := isCtyPrimitiveValueValid(a, b)
		if !valid {
			return fmt.Errorf("should be %s, was: %s", a.GoString(), b.GoString())
		}
	case listCtyType:
		valid := isCtyListValid(a, b)
		if !valid {
			return fmt.Errorf("should contain %s, received: %s", a.GoString(), b.GoString())
		}
	case mapCtyType:
		valid := isCtyMapValid(a, b)
		if !valid {
			return fmt.Errorf("should contain %s, received: %s", a.GoString(), b.GoString())
		}
	default:
		return fmt.Errorf("non-implemented type - should be %s, received: %s", a.GoString(), b.GoString())
	}

	return nil
}

type ctyType int

const (
	unknownCtyType = iota
	primitiveCtyType
	listCtyType
	mapCtyType
)

func getCtyType(a cty.Value) ctyType {
	if a.Type().IsPrimitiveType() {
		return primitiveCtyType
	}

	switch {
	case a.Type().IsListType():
		return listCtyType

	// Adding the other cases to make it easier in the
	// future to build logic for more types.
	case a.Type().IsMapType():
		return mapCtyType
	case a.Type().IsSetType():
		return unknownCtyType
	case a.Type().IsObjectType():
		return unknownCtyType
	case a.Type().IsTupleType():
		return unknownCtyType
	case a.Type().IsCapsuleType():
		return unknownCtyType
	}

	return unknownCtyType
}
