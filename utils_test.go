package utils

import (
	"testing"
)

func TestEqualFloat64(t *testing.T) {
	type args struct {
		f1 interface{}
		f2 interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{"TestEqual", args{52, "51"}, 1, false},
		{"one", args{52, "51.5"}, 1, false},
		{"one", args{52.01, "51"}, 1, false},
		{"one", args{52.01, "51.5"}, 1, false},
		{"one", args{"52", "51"}, 1, false},
		{"one", args{"52", "51.5"}, 1, false},
		{"one", args{"52.5", "51"}, 1, false},
		{"one", args{"52.5", "51.5"}, 1, false},

		{"one", args{52, "52"}, 0, false},
		{"one", args{52, "52.00"}, 0, false},
		{"one", args{52.00, "52"}, 0, false},
		{"one", args{52.00, "52.00"}, 0, false},

		{"one", args{51, "52"}, -1, false},
		{"one", args{51, "52.5"}, -1, false},
		{"one", args{51.5, "52"}, -1, false},
		{"one", args{51.5, "52.5"}, -1, false},
		{"one", args{"51.5", "52"}, -1, false},
		{"one", args{"51.5", "52.5"}, -1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EqualFloat64(tt.args.f1, tt.args.f2)
			if (err != nil) != tt.wantErr {
				t.Errorf("EqualFloat64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EqualFloat64() = %v, want %v", got, tt.want)
			}
		})
	}
}
