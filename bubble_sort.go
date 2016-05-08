package th_tools

func BubbleSortInt(value []int) {
	for i := 0; i < len(value)-1; i++ {
		for j := i + 1; j < len(value); j++ {
			if value[i] > value[j] {
				value[i], value[j] = value[j], value[i]
			}
		}
	}
}

func BubbleSortString(value []string) {
	for i := 0; i < len(value)-1; i++ {
		for j := i + 1; j < len(value); j++ {
			if value[i] > value[j] {
				value[i], value[j] = value[j], value[i]
			}
		}
	}
}
