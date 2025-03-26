package model

import (
	"fmt"

	"github.com/ybkuroki/go-webapp-sample/config"
	"github.com/ybkuroki/go-webapp-sample/repository"
	"golang.org/x/crypto/bcrypt"
)

// Account defines struct of account data.
type Account struct {
	ID          uint       `gorm:"primary_key" json:"id"`
	Name        string     `json:"name"`
	Password    string     `json:"-"`
	AuthorityID uint       `json:"authority_id"`
	Authority   *Authority `json:"authority"`
}

// RecordAccount defines struct represents the record of the database.
type RecordAccount struct {
	ID            uint
	Name          string
	Password      string
	AuthorityID   uint
	AuthorityName string
}

const selectAccount = "select a.id as id, a.name as name, a.password as password," +
	" r.id as authority_id, r.name as authority_name " +
	" from account_master a inner join authority_master r on a.authority_id = r.id "

// TableName returns the table name of account struct and it is used by gorm.
func (Account) TableName() string {
	return "account_master"
}

// NewAccount is constructor.
func NewAccount(name string, password string, authorityID uint) *Account {
	return &Account{Name: name, Password: password, AuthorityID: authorityID}
}

// NewAccountWithPlainPassword is constructor. It encodes plain text password using bcrypt.
func NewAccountWithPlainPassword(name string, password string, authorityID uint) (*Account, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), config.PasswordHashCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	return &Account{Name: name, Password: string(hashed), AuthorityID: authorityID}, nil
		return nil, fmt.Errorf("failed to hash password: %w", err)
	if len(name) > 255 {
		return nil, fmt.Errorf("name is too long")
	}

	var rec RecordAccount
	result := rep.Raw(selectAccount+" where a.name = ?", name).Scan(&rec)
	if result.Error != nil {
		return nil, fmt.Errorf("error finding account: %w", result.Error)
	}

	if result.RowsAffected == 0 {
	// Check if an account with the same name already exists
	var existingAccount Account
	result := rep.Where("name = ?", a.Name).First(&existingAccount)
	if result.Error == nil {
		// An account with this name already exists
		return nil, fmt.Errorf("an account with the name %s already exists", a.Name)
	} else if !rep.IsRecordNotFoundError(result.Error) {
	// Create the new account
	if err := rep.Create(a).Error; err != nil {
	if err := rep.Create(a).Error; err != nil {
		return nil, fmt.Errorf("an account with the name %s already exists", a.Name)
	} else if !rep.IsRecordNotFoundError(result.Error) {
		// An error occurred that wasn't "record not found"
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("account not found")
	}

	account := convertToAccount(&rec)

	result := rep.Exec(query)
	if result.Error != nil {
		return nil, result.Error
	}

	if err := rep.Select("name", "password", "authority_id").Create(a).Error; err != nil {
		return nil, err
	}
	return a, nil
}

func convertToAccount(rec *RecordAccount) *Account {
	r := &Authority{ID: rec.AuthorityID, Name: rec.AuthorityName}
	return &Account{ID: rec.ID, Name: rec.Name, Password: rec.Password, AuthorityID: rec.AuthorityID, Authority: r}
}

// ToString is return string of object
func (a *Account) ToString() string {
	return toString(a)
}
