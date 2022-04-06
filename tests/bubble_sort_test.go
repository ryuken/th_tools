package tests

import (
	"testing"

	tools "github.com/ryuken/th_tools"
	"github.com/stretchr/testify/assert"
)

func TestSortInt(t *testing.T) {
	run := tools.BubbleSortInt

	result := []int{1, 2, 4, 5, 8}

	list1 := []int{5, 1, 4, 2, 8}
	list2 := []int{1, 4, 2, 5, 8}
	list3 := []int{1, 2, 4, 5, 8}

	run(list1)
	run(list2)
	run(list3)

	assert.Equal(t, result, list1, "they should be equal")
	assert.Equal(t, result, list2, "they should be equal")
	assert.Equal(t, result, list3, "they should be equal")
}

func TestSortString(t *testing.T) {
	run := tools.BubbleSortString

	result1 := []string{"aap", "bart", "dam", "drol", "eekhoorn"}
	result2 := []string{"a", "b", "d", "e", "i"}

	list1 := []string{"eekhoorn", "aap", "drol", "bart", "dam"}
	list2 := []string{"a", "d", "b", "e", "i"}
	list3 := []string{"a", "b", "d", "e", "i"}

	run(list1)
	run(list2)
	run(list3)

	assert.Equal(t, result1, list1, "they should be equal")
	assert.Equal(t, result2, list2, "they should be equal")
	assert.Equal(t, result2, list3, "they should be equal")
}
