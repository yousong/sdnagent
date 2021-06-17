package modules

import "yunion.io/x/onecloud/pkg/mcclient/modulebase"

type SBillsDimensionManager struct {
	*modulebase.ResourceManager
}

var (
	BillingDimensionManager         *SBillsDimensionManager
	BillingDimensionAnalysisManager *SBillsDimensionManager
)

func NewBillingDimensionManager() *SBillsDimensionManager {
	man := NewMeterManager("billsdimension", "billsdimensions",
		[]string{"id", "name", "dimension_type", "dimension_items"},
		[]string{})
	return &SBillsDimensionManager{
		ResourceManager: &man,
	}
}

func NewBillingDimensionAnalysisManager() *SBillsDimensionManager {
	man := NewMeterManager("billsdimensionsanalysis", "billsdimensionsanalysis",
		[]string{"id", "name", "usage_type", "resource_type", "brand", "description"},
		[]string{})
	return &SBillsDimensionManager{
		ResourceManager: &man,
	}
}

func init() {
	BillingDimensionManager = NewBillingDimensionManager()
	BillingDimensionAnalysisManager = NewBillingDimensionAnalysisManager()
	register(BillingDimensionManager)
	register(BillingDimensionAnalysisManager)
}
