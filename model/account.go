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

// NewAccount is a deprecated constructor. Use NewAccountWithPlainPassword instead.
// Deprecated: This function does not hash the password and is insecure.
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
}

// FindByName returns the account that fully matches the given account name.
func (a *Account) FindByName(rep repository.Repository, name string) (*Account, error) {
	var rec RecordAccount
	err := rep.Raw(selectAccount+" where a.name = ?", name).Scan(&rec).Error
	if err != nil {
		if rep.IsRecordNotFoundError(err) {
			return nil, nil // No account found, not necessarily an error
		}
		return nil, fmt.Errorf("error finding account: %w", err)
	}

	if rec.ID == 0 { // Check if a record was actually found
		return nil, nil
	}

	account := convertToAccount(&rec)
	return account, nil
}

// Create persists this account data.
func (a *Account) Create(rep repository.Repository) (*Account, error) {
	// Check if an account with the same name already exists
	var existingAccount Account
	if err := rep.Where("name = ?", a.Name).First(&existingAccount).Error; err == nil {
		return nil, fmt.Errorf("account with name %s already exists", a.Name)
	} else if !rep.IsRecordNotFoundError(err) {
		return nil, err
	}

	// Create the new account
	if err := rep.Select("name", "password", "authority_id").Create(a).Error; err != nil {
		return nil, err
	}
	return a, nil
}

func convertToAccount(rec *RecordAccount) *Account {
	r := &Authority{ID: rec.AuthorityID, Name: rec.AuthorityName}
	return &Account{ID: rec.ID, Name: rec.Name, Password: rec.Password, AuthorityID: rec.AuthorityID, Authority: r}
}
