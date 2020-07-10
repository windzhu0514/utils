package dbpool_test

import (
	"database/sql"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/windzhu0514/go-utils/database/dbpool"
)

var dbPool *dbpool.DBPool

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	cfg := &dbpool.Config{
		DriverName: "mysql",
		Master: dbpool.ConnOpt{
			DSN:            "root:123456@tcp(localhost:3306)/busticket?charset=utf8",
			MaxConns:       10,
			IdleConns:      2,
			ConLifeSeconds: 30 * time.Second,
		},
		Slave: dbpool.ConnOpt{
			DSN:            "root:123456@tcp(localhost:3306)/busticket?charset=utf8",
			MaxConns:       0,
			IdleConns:      0,
			ConLifeSeconds: 30 * time.Second,
		},
	}
	var err error
	dbPool, err = dbpool.NewDBPool(cfg)
	if err != nil {
		log.Fatal(err)
	}
}

func TestDBPool_Exec(t *testing.T) {
	result, err := dbPool.Exec("UPDATE robots SET siteId=? WHERE id=?", 1001, 10041)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(result.RowsAffected())
}

func ExampleDBPool_ExecContext() {

}

func TestDBPool_Query(t *testing.T) {
	err := dbPool.Query(func(rows *sql.Rows) error {
		for rows.Next() {
			var id int
			var siteId int
			var robotName string
			rows.Scan(&id, &siteId, &robotName)
			fmt.Println(id, siteId, robotName)
		}
		return nil
	}, "SELECT id,siteId,robot_name FROM robots WHERE id BETWEEN ? AND ?", 10041, 10043)
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleDBPool_QueryContext() {

}

func ExampleDBPool_QueryRow() {
	result, err := dbPool.Exec("UPDATE robots SET siteId=? WHERE id=?", 1001, 10041)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(result.RowsAffected())
}

func ExampleDBPool_QueryRowContext() {

}

func ExampleDBPool_chooseDB() {

}
