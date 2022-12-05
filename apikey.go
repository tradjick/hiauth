package hiauth

import (
	"encoding/json"
	"github.com/tradjick/hidb"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type ApiKey struct {
	ID        uint32 `path:"apikeyid" gorm:"primaryKey;autoIncrement"`
	Key       string `path:"apikey" gorm:"uniqueIndex;not null"`
	Policy    datatypes.JSON
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

//todo add in key expiration

func (ak *ApiKey) LoadByKey(k string) (bool, error) {
	ak.Key = k
	r := hidb.FetchDB().Where(&ak, "Key").Limit(1).Find(&ak)
	if r.RowsAffected == 0 || r.Error != nil {
		return false, r.Error
	}
	return true, nil
}

func (ak *ApiKey) LoadByID(id uint32) (bool, error) {
	ak.ID = id
	r := hidb.FetchDB().Where(&ak, "ID").Limit(1).Find(&ak)
	if r.RowsAffected == 0 || r.Error != nil {
		return false, r.Error
	}
	return true, nil
}

func (ak *ApiKey) fetchPolicy() (policy, error) {
	p := new(policy)
	err := json.Unmarshal(ak.Policy, &p)
	return *p, err
}

func (ak *ApiKey) permissionsForService(s service) (permission, error) {
	p, err := ak.fetchPolicy()
	return p[s], err
}

func (ak *ApiKey) conditionsForAction(s service, a action) (Conditions, error) {
	perms, err := ak.permissionsForService(s)
	return perms[a], err
}

func (ak *ApiKey) Conditions(s service, a action) (Conditions, error) {
	wc, err := ak.conditionsForAction(s, "*")
	if err != nil {
		return Conditions{}, err
	}
	c, err := ak.conditionsForAction(s, a)
	if err != nil {
		return Conditions{}, err
	}
	o := make(Conditions, 0, len(wc)+len(c))
	o = append(o, wc...)
	o = append(o, c...)
	return uniqueConditions(o), err
}

func (ak *ApiKey) IsValid() bool {
	//todo check for key expiry, check owners status, check owners deletion
	return true
}

func uniqueConditions(cs Conditions) Conditions {
	u := make([]Condition, 0, len(cs))
	m := make(map[Condition]bool)
	for _, val := range cs {
		if _, ok := m[val]; !ok {
			m[val] = true
			u = append(u, val)
		}
	}
	return u
}
