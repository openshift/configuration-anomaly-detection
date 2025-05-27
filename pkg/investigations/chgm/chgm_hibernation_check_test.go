package chgm

import (
	"reflect"
	"testing"
	"time"

	servicelogsv1 "github.com/openshift-online/ocm-sdk-go/servicelogs/v1"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
)

func init() {
	// Initialize the logger
	logging.RawLogger = logging.InitLogger("info")
}

func TestCreateHibernationTimeLine(t *testing.T) {
	type args struct {
		clusterStateUpdates []*servicelogsv1.LogEntry
	}
	hibernationStartTime := time.Date(2023, 0o1, 0o1, 0o0, 0o0, 0o0, 0o0, time.Local)
	hibernationStopTime := time.Date(2023, 0o2, 0o1, 0o0, 0o0, 0o0, 0o0, time.Local)
	hibernationStart, _ := servicelogsv1.NewLogEntry().Timestamp(hibernationStartTime).Summary(hibernationStartEvent).Build()
	hibernationEnd, _ := servicelogsv1.NewLogEntry().Timestamp(hibernationStopTime).Summary(hibernationEndEvent).Build()
	var emptyHibernationSlice []*hibernationPeriod
	tests := []struct {
		name string
		args args
		want []*hibernationPeriod
	}{
		{
			name: "Hibernation with start and end",
			args: args{
				clusterStateUpdates: []*servicelogsv1.LogEntry{
					hibernationStart,
					hibernationEnd,
				},
			},
			want: []*hibernationPeriod{
				{
					HibernationDuration: hibernationStopTime.Sub(hibernationStartTime),
					DehibernationTime:   hibernationStopTime,
				},
			},
		},
		{
			name: "Hibernation without end is not part of the return",
			args: args{
				clusterStateUpdates: []*servicelogsv1.LogEntry{
					hibernationStart,
				},
			},
			want: emptyHibernationSlice,
		},
		{
			name: "Hibernation without start is not part of the return",
			args: args{
				clusterStateUpdates: []*servicelogsv1.LogEntry{
					hibernationEnd,
				},
			},
			want: emptyHibernationSlice,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := createHibernationTimeLine(tt.args.clusterStateUpdates); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateHibernationTimeLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHibernatedTooLong(t *testing.T) {
	type args struct {
		hibernations []*hibernationPeriod
		now          time.Time
	}
	hibernationStartTime := time.Date(2023, 0o1, 0o1, 0o0, 0o0, 0o0, 0o0, time.Local)
	hibernationShortStopTime := time.Date(2023, 0o1, 11, 0o0, 0o0, 0o0, 0o0, time.Local)
	hibernationLongStopTime := time.Date(2023, 0o2, 11, 0o0, 0o0, 0o0, 0o0, time.Local)
	shortHibernation := &hibernationPeriod{
		HibernationDuration: hibernationShortStopTime.Sub(hibernationStartTime),
		DehibernationTime:   hibernationShortStopTime,
	}
	longHibernation := &hibernationPeriod{
		HibernationDuration: hibernationLongStopTime.Sub(hibernationStartTime),
		DehibernationTime:   hibernationLongStopTime,
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
		{
			name: "Cluster that hibernated for 10 days is ok",
			args: args{
				hibernations: []*hibernationPeriod{shortHibernation},
				now:          hibernationShortStopTime.Add(1 * time.Hour),
			},
			want: false,
		},
		{
			name: "Cluster that hibernated for 30+ days is too long",
			args: args{
				hibernations: []*hibernationPeriod{longHibernation},
				now:          hibernationLongStopTime.Add(1 * time.Hour),
			},
			want: true,
		},
		{
			name: "Cluster that never hibernated is ok",
			args: args{},
			want: false,
		},
		{
			name: "Cluster that woke up for 2+ hours ago ok",
			args: args{
				hibernations: []*hibernationPeriod{longHibernation},
				now:          hibernationLongStopTime.Add(3 * time.Hour),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hibernatedTooLong(tt.args.hibernations, tt.args.now)
			if got != tt.want {
				t.Errorf("HibernatedTooLong() = %v, want %v", got, tt.want)
			}
		})
	}
}
