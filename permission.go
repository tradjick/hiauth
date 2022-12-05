package hiauth

type Condition string

type Conditions []Condition

func (cs *Conditions) contains(c Condition) (found bool) {
	found = false
	for _, val := range *cs {
		found = val == c
		if found {
			break
		}
	}
	return
}

type action string

type permission map[action]Conditions

type service string

type policy map[service]permission
