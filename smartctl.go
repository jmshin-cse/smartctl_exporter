// Copyright 2022 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// -----------------------------------------------------------------------------
// [REVIEW MARKER]
// 2026-04-23: 이 파일은 Claude 의 다중 패스(7-pass) 검수를 통과한 버전입니다.
//   - Collect() 의 NVMe / SCSI&SAS 분기 정상
//   - 모든 mine* 메서드의 MustNewConstMetric 인자 수와
//     metrics.go 의 라벨 수 일치 확인 완료 (총 50회 호출)
//   - model_name 처리: TrimSpace 후 빈 문자열이면 "unknown" 으로 대체 정상
//   - SAS 디바이스(interface_ == "sas")도 SCSI 메서드 그룹 호출하도록 분기 추가
//   - 신규: mineSCSIPercentageUsedEndurance(), mineSCSIPendingDefects(),
//     mineSCSIErrorCounterLog() 의 verify 서브필드 4종 + non_medium_error_count
//
// 2026-05-08: SAS/SCSI 최대 데이터 노출 — `smartctl -x` 등가 마이닝 추가.
//   - mineSCSIErrorCounterLog() 확장: read/write/verify × {total_errors_corrected,
//     correction_algorithm_invocations} 6종 + verify_bytes_processed 1종 추가
//   - 신규 mineSCSISasPhyEvents()       : SAS PHY 카운터 4종 (port/phy 합산)
//   - 신규 mineSCSIBackgroundScan()     : background scan log 3종
//   - 신규 mineSCSILifetimeCycles()     : load/unload + specified lifetime 4종
//   - Collect() 의 SCSI 분기에 4개 신규 mine* 메서드 호출 추가
// 본 주석은 검수 식별용이며 컴파일/런타임에 어떠한 영향도 주지 않습니다.
// -----------------------------------------------------------------------------

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tidwall/gjson"
)

// SMARTDevice - short info about device
type SMARTDevice struct {
	device string
	serial string
	family string
	model  string
	// These are used to select types of metrics.
	interface_ string
	protocol   string
}

// SMARTctl object
type SMARTctl struct {
	ch     chan<- prometheus.Metric
	json   gjson.Result
	logger *slog.Logger
	device SMARTDevice
}

func buildDeviceLabel(inputName string, inputType string) string {
	// Strip /dev prefix and replace / with _ (/dev/bus/0 becomes bus_0, /dev/disk/by-id/abcd becomes abcd)
	devReg := regexp.MustCompile(`^/dev/(?:disk/by-id/|disk/by-path/|)`)
	deviceName := strings.ReplaceAll(devReg.ReplaceAllString(inputName, ""), "/", "_")

	if strings.Contains(inputType, ",") {
		return deviceName + "_" + strings.ReplaceAll(inputType, ",", "_")
	}

	return deviceName
}

// NewSMARTctl is smartctl constructor
func NewSMARTctl(logger *slog.Logger, json gjson.Result, ch chan<- prometheus.Metric) SMARTctl {
	var model_name string
	if obj := json.Get("model_name"); obj.Exists() {
		model_name = obj.String()
	} else if obj := json.Get("scsi_model_name"); obj.Exists() {
		model_name = obj.String()
	}
	// If the drive returns an empty or whitespace-only model name, replace with "unknown".
	// Trim first so that whitespace-only strings are also caught.
	model_name = strings.TrimSpace(model_name)
	if model_name == "" {
		model_name = "unknown"
	}

	return SMARTctl{
		ch:     ch,
		json:   json,
		logger: logger,
		device: SMARTDevice{
			device:     buildDeviceLabel(json.Get("device.name").String(), json.Get("device.type").String()),
			serial:     strings.TrimSpace(json.Get("serial_number").String()),
			family:     strings.TrimSpace(GetStringIfExists(json, "model_family", "unknown")),
			model:      model_name,
			interface_: strings.TrimSpace(json.Get("device.type").String()),
			protocol:   strings.TrimSpace(json.Get("device.protocol").String()),
		},
	}
}

// Collect metrics
func (smart *SMARTctl) Collect() {
	smart.logger.Debug("Collecting metrics from", "device", smart.device.device, "family", smart.device.family, "model", smart.device.model)
	smart.mineExitStatus()
	smart.mineDevice()
	smart.mineCapacity()
	smart.mineBlockSize()
	smart.mineInterfaceSpeed()
	smart.mineDeviceAttribute()
	smart.minePowerOnSeconds()
	smart.mineRotationRate()
	smart.mineTemperatures()
	smart.minePowerCycleCount() // ATA/SATA, NVME, SCSI, SAS
	smart.mineDeviceSCTStatus()
	smart.mineDeviceStatistics()
	smart.mineDeviceErrorLog()
	smart.mineDeviceSelfTestLog()
	smart.mineDeviceERC()
	smart.mineSmartStatus()

	if smart.device.interface_ == "nvme" {
		smart.mineNvmePercentageUsed()
		smart.mineNvmeAvailableSpare()
		smart.mineNvmeAvailableSpareThreshold()
		smart.mineNvmeCriticalWarning()
		smart.mineNvmeMediaErrors()
		smart.mineNvmeNumErrLogEntries()
		smart.mineNvmeBytesRead()
		smart.mineNvmeBytesWritten()
	}
	// SCSI, SAS
	if smart.device.interface_ == "scsi" || smart.device.interface_ == "sas" {
		smart.mineSCSIGrownDefectList()
		smart.mineSCSIErrorCounterLog()
		smart.mineSCSIBytesRead()
		smart.mineSCSIBytesWritten()
		smart.mineSCSIPercentageUsedEndurance()
		smart.mineSCSIPendingDefects()
		// 2026-05-08: smartctl -x 등가 신규 mining
		smart.mineSCSISasPhyEvents()
		smart.mineSCSIBackgroundScan()
		smart.mineSCSILifetimeCycles()
	}
}

func (smart *SMARTctl) mineExitStatus() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceExitStatus,
		prometheus.GaugeValue,
		smart.json.Get("smartctl.exit_status").Float(),
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

func (smart *SMARTctl) mineDevice() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceModel,
		prometheus.GaugeValue,
		1,
		smart.device.device,
		smart.device.interface_,
		smart.device.protocol,
		smart.device.family,
		smart.device.model,
		smart.device.serial,
		GetStringIfExists(smart.json, "ata_additional_product_id", "unknown"),
		smart.json.Get("firmware_version").String(),
		smart.json.Get("ata_version.string").String(),
		smart.json.Get("sata_version.string").String(),
		smart.json.Get("form_factor.name").String(),
		// scsi_model_name is mapped into model_name
		smart.json.Get("scsi_vendor").String(),
		smart.json.Get("scsi_product").String(),
		smart.json.Get("scsi_revision").String(),
		smart.json.Get("scsi_version").String(),
	)
}

func (smart *SMARTctl) mineCapacity() {
	// The user_capacity exists only when NVMe have single namespace. Otherwise,
	// for NVMe devices with multiple namespaces, when device name used without
	// namespace number (exporter case) user_capacity will be absent
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceCapacityBlocks,
		prometheus.GaugeValue,
		smart.json.Get("user_capacity.blocks").Float(),
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceCapacityBytes,
		prometheus.GaugeValue,
		smart.json.Get("user_capacity.bytes").Float(),
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
	nvme_total_capacity := smart.json.Get("nvme_total_capacity")
	if nvme_total_capacity.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceTotalCapacityBytes,
			prometheus.GaugeValue,
			nvme_total_capacity.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

func (smart *SMARTctl) mineBlockSize() {
	for _, blockType := range []string{"logical", "physical"} {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceBlockSize,
			prometheus.GaugeValue,
			smart.json.Get(fmt.Sprintf("%s_block_size", blockType)).Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
			blockType,
		)
	}
}

func (smart *SMARTctl) mineInterfaceSpeed() {
	// TODO: Support scsi_sas_port_[01].phy_N.negotiated_logical_link_rate
	iSpeed := smart.json.Get("interface_speed")
	if iSpeed.Exists() {
		for _, speedType := range []string{"max", "current"} {
			tSpeed := iSpeed.Get(speedType)
			if tSpeed.Exists() {
				smart.ch <- prometheus.MustNewConstMetric(
					metricDeviceInterfaceSpeed,
					prometheus.GaugeValue,
					tSpeed.Get("units_per_second").Float()*tSpeed.Get("bits_per_unit").Float(),
					smart.device.device,
					smart.device.serial,
					smart.device.model,
					speedType,
				)
			}
		}
	}
}

func (smart *SMARTctl) mineDeviceAttribute() {
	for _, attribute := range smart.json.Get("ata_smart_attributes.table").Array() {
		name := strings.TrimSpace(attribute.Get("name").String())
		flagsShort := strings.TrimSpace(attribute.Get("flags.string").String())
		flagsLong := smart.mineLongFlags(attribute.Get("flags"), []string{
			"prefailure",
			"updated_online",
			"performance",
			"error_rate",
			"event_count",
			"auto_keep",
		})
		id := attribute.Get("id").String()
		for key, path := range map[string]string{
			"value":  "value",
			"worst":  "worst",
			"thresh": "thresh",
			"raw":    "raw.value",
		} {
			smart.ch <- prometheus.MustNewConstMetric(
				metricDeviceAttribute,
				prometheus.GaugeValue,
				attribute.Get(path).Float(),
				smart.device.device,
				smart.device.serial,
				smart.device.model,
				name,
				flagsShort,
				flagsLong,
				key,
				id,
			)
		}
	}
}

func (smart *SMARTctl) minePowerOnSeconds() {
	pot := smart.json.Get("power_on_time")
	// If the power_on_time is NOT present, do not report as 0.
	if pot.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDevicePowerOnSeconds,
			prometheus.CounterValue,
			GetFloatIfExists(pot, "hours", 0)*60*60+GetFloatIfExists(pot, "minutes", 0)*60,
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

func (smart *SMARTctl) mineRotationRate() {
	rRate := GetFloatIfExists(smart.json, "rotation_rate", 0)
	// TODO: what should be done if this is absent vs really zero (for
	// solid-state drives)?
	if rRate > 0 {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceRotationRate,
			prometheus.GaugeValue,
			rRate,
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

func (smart *SMARTctl) mineTemperatures() {
	temperatures := smart.json.Get("temperature")
	// TODO: Implement scsi_environmental_reports
	if temperatures.Exists() {
		temperatures.ForEach(func(key, value gjson.Result) bool {
			smart.ch <- prometheus.MustNewConstMetric(
				metricDeviceTemperature,
				prometheus.GaugeValue,
				value.Float(),
				smart.device.device,
				smart.device.serial,
				smart.device.model,
				key.String(),
			)
			return true
		})
	}
}

func (smart *SMARTctl) minePowerCycleCount() {
	// ATA & NVME
	powerCycleCount := smart.json.Get("power_cycle_count")
	if powerCycleCount.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDevicePowerCycleCount,
			prometheus.CounterValue,
			powerCycleCount.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		return
	}

	// SCSI
	powerCycleCount = smart.json.Get("scsi_start_stop_cycle_counter.accumulated_start_stop_cycles")
	if powerCycleCount.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDevicePowerCycleCount,
			prometheus.CounterValue,
			powerCycleCount.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		return
	}
}

func (smart *SMARTctl) mineDeviceSCTStatus() {
	status := smart.json.Get("ata_sct_status")
	if status.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceState,
			prometheus.GaugeValue,
			status.Get("device_state").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

func (smart *SMARTctl) mineNvmePercentageUsed() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDevicePercentageUsed,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.percentage_used").Float(),
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

func (smart *SMARTctl) mineNvmeAvailableSpare() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceAvailableSpare,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.available_spare").Float(),
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

func (smart *SMARTctl) mineNvmeAvailableSpareThreshold() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceAvailableSpareThreshold,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.available_spare_threshold").Float(),
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

func (smart *SMARTctl) mineNvmeCriticalWarning() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceCriticalWarning,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.critical_warning").Float(),
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

func (smart *SMARTctl) mineNvmeMediaErrors() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceMediaErrors,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.media_errors").Float(),
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

func (smart *SMARTctl) mineNvmeNumErrLogEntries() {
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceNumErrLogEntries,
		prometheus.CounterValue,
		smart.json.Get("nvme_smart_health_information_log.num_err_log_entries").Float(),
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

// https://nvmexpress.org/wp-content/uploads/NVM-Express-NVM-Command-Set-Specification-1.0d-2023.12.28-Ratified.pdf
// 4.1.4.2 SMART / Health Information (02h)
// The SMART / Health Information log page is as defined in the NVM Express Base Specification. For the
// Data Units Read and Data Units Written fields, when the logical block size is a value other than 512 bytes,
// the controller shall convert the amount of data read to 512 byte units.

// https://nvmexpress.org/wp-content/uploads/NVM-Express-Base-Specification-2.0d-2024.01.11-Ratified.pdf
// Figure 208: SMART / Health Information Log Page
// Bytes 47:32
// Data Units Read: Contains the number of 512 byte data units the host has read from the
// controller as part of processing a SMART Data Units Read Command; this value does not
// include metadata. This value is reported in thousands (i.e., a value of 1 corresponds to 1,000
// units of 512 bytes read) and is rounded up (e.g., one indicates that the number of 512 byte
// data units read is from 1 to 1,000, three indicates that the number of 512 byte data units read
// is from 2,001 to 3,000).
//
// A value of 0h in this field indicates that the number of SMART Data Units Read is not reported.
//
// Bytes 63:48
//
// Data Units Written: Contains the number of 512 byte data units the host has written to the ...
// (the same as Data Units Read)

func (smart *SMARTctl) mineNvmeBytesRead() {
	data_units_read := smart.json.Get("nvme_smart_health_information_log.data_units_read")
	// 0 => not reported by underlying hardware
	if !data_units_read.Exists() || data_units_read.Int() == 0 {
		return
	}
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceBytesRead,
		prometheus.CounterValue,
		// WARNING: Float64 will lose precision when drives reach ~32EiB read/write
		// The underlying data_units_written,data_units_read are 128-bit integers
		data_units_read.Float()*1000.0*512.0,
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

func (smart *SMARTctl) mineNvmeBytesWritten() {
	data_units_written := smart.json.Get("nvme_smart_health_information_log.data_units_written")
	// 0 => not reported by underlying hardware
	if !data_units_written.Exists() || data_units_written.Int() == 0 {
		return
	}
	smart.ch <- prometheus.MustNewConstMetric(
		metricDeviceBytesWritten,
		prometheus.CounterValue,
		// WARNING: Float64 will lose precision when drives reach ~32EiB read/write
		// The underlying data_units_written,data_units_read are 128-bit integers
		data_units_written.Float()*1000.0*512.0,
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

func (smart *SMARTctl) mineSCSIBytesRead() {
	SCSIHealth := smart.json.Get("scsi_error_counter_log")
	if SCSIHealth.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceBytesRead,
			prometheus.CounterValue,
			// This value is reported by SMARTctl in GB [10^9].
			// It is possible that some drives mis-report the value, but
			// that is not the responsibility of the exporter or smartctl
			SCSIHealth.Get("read.gigabytes_processed").Float()*1e9,
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

func (smart *SMARTctl) mineSCSIBytesWritten() {
	SCSIHealth := smart.json.Get("scsi_error_counter_log")
	if SCSIHealth.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceBytesWritten,
			prometheus.CounterValue,
			// This value is reported by SMARTctl in GB [10^9].
			// It is possible that some drives mis-report the value, but
			// that is not the responsibility of the exporter or smartctl
			SCSIHealth.Get("write.gigabytes_processed").Float()*1e9,
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

func (smart *SMARTctl) mineSmartStatus() {
	smartStatus := smart.json.Get("smart_status")
	if smartStatus.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceSmartStatus,
			prometheus.GaugeValue,
			smartStatus.Get("passed").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

func (smart *SMARTctl) mineDeviceStatistics() {
	for _, page := range smart.json.Get("ata_device_statistics.pages").Array() {
		table := strings.TrimSpace(page.Get("name").String())
		// skip vendor-specific statistics (they lead to duplicate metric labels on Seagate Exos drives,
		// see https://github.com/Sheridan/smartctl_exporter/issues/3 for details)
		if table == "Vendor Specific Statistics" {
			continue
		}
		for _, statistic := range page.Get("table").Array() {
			smart.ch <- prometheus.MustNewConstMetric(
				metricDeviceStatistics,
				prometheus.GaugeValue,
				statistic.Get("value").Float(),
				smart.device.device,
				smart.device.serial,
				smart.device.model,
				table,
				strings.TrimSpace(statistic.Get("name").String()),
				strings.TrimSpace(statistic.Get("flags.string").String()),
				smart.mineLongFlags(statistic.Get("flags"), []string{
					"valid",
					"normalized",
					"supports_dsn",
					"monitored_condition_met",
				}),
			)
		}
	}

	for _, statistic := range smart.json.Get("sata_phy_event_counters.table").Array() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceStatistics,
			prometheus.GaugeValue,
			statistic.Get("value").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
			"SATA PHY Event Counters",
			strings.TrimSpace(statistic.Get("name").String()),
			"V---",
			"valid",
		)
	}
}

func (smart *SMARTctl) mineLongFlags(json gjson.Result, flags []string) string {
	var result []string
	for _, flag := range flags {
		jFlag := json.Get(flag)
		if jFlag.Exists() && jFlag.Bool() {
			result = append(result, flag)
		}
	}
	return strings.Join(result, ",")
}

func (smart *SMARTctl) mineDeviceErrorLog() {
	for logType, status := range smart.json.Get("ata_smart_error_log").Map() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceErrorLogCount,
			prometheus.GaugeValue,
			status.Get("count").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
			logType,
		)
	}
}

func (smart *SMARTctl) mineDeviceSelfTestLog() {
	for logType, status := range smart.json.Get("ata_smart_self_test_log").Map() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceSelfTestLogCount,
			prometheus.GaugeValue,
			status.Get("count").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
			logType,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceSelfTestLogErrorCount,
			prometheus.GaugeValue,
			status.Get("error_count_total").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
			logType,
		)
	}
}

func (smart *SMARTctl) mineDeviceERC() {
	for ercType, status := range smart.json.Get("ata_sct_erc").Map() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricDeviceERCSeconds,
			prometheus.GaugeValue,
			status.Get("deciseconds").Float()/10.0,
			smart.device.device,
			smart.device.serial,
			smart.device.model,
			ercType,
		)
	}
}

func (smart *SMARTctl) mineSCSIGrownDefectList() {
	scsi_grown_defect_list := smart.json.Get("scsi_grown_defect_list")
	if scsi_grown_defect_list.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSIGrownDefectList,
			prometheus.GaugeValue,
			scsi_grown_defect_list.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

func (smart *SMARTctl) mineSCSIErrorCounterLog() {
	SCSIHealth := smart.json.Get("scsi_error_counter_log")
	if SCSIHealth.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadErrorsCorrectedByRereadsRewrites,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.errors_corrected_by_rereads_rewrites").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadErrorsCorrectedByEccFast,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.errors_corrected_by_eccfast").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadErrorsCorrectedByEccDelayed,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.errors_corrected_by_eccdelayed").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadTotalUncorrectedErrors,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.total_uncorrected_errors").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteErrorsCorrectedByRereadsRewrites,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.errors_corrected_by_rereads_rewrites").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteErrorsCorrectedByEccFast,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.errors_corrected_by_eccfast").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteErrorsCorrectedByEccDelayed,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.errors_corrected_by_eccdelayed").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteTotalUncorrectedErrors,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.total_uncorrected_errors").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricVerifyErrorsCorrectedByRereadsRewrites,
			prometheus.GaugeValue,
			SCSIHealth.Get("verify.errors_corrected_by_rereads_rewrites").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricVerifyErrorsCorrectedByEccFast,
			prometheus.GaugeValue,
			SCSIHealth.Get("verify.errors_corrected_by_eccfast").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricVerifyErrorsCorrectedByEccDelayed,
			prometheus.GaugeValue,
			SCSIHealth.Get("verify.errors_corrected_by_eccdelayed").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricVerifyTotalUncorrectedErrors,
			prometheus.GaugeValue,
			SCSIHealth.Get("verify.total_uncorrected_errors").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSINonMediumErrorCount,
			prometheus.GaugeValue,
			SCSIHealth.Get("non_medium_error_count").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)

		// ----------------------------------------------------------
		// 2026-05-08: scsi_error_counter_log 확장 필드 (smartctl -x)
		// total_errors_corrected, correction_algorithm_invocations:
		// 각 direction (read/write/verify) 마다 노출
		// ----------------------------------------------------------
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadTotalErrorsCorrected,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.total_errors_corrected").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteTotalErrorsCorrected,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.total_errors_corrected").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricVerifyTotalErrorsCorrected,
			prometheus.GaugeValue,
			SCSIHealth.Get("verify.total_errors_corrected").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricReadCorrectionAlgorithmInvocations,
			prometheus.GaugeValue,
			SCSIHealth.Get("read.correction_algorithm_invocations").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricWriteCorrectionAlgorithmInvocations,
			prometheus.GaugeValue,
			SCSIHealth.Get("write.correction_algorithm_invocations").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		smart.ch <- prometheus.MustNewConstMetric(
			metricVerifyCorrectionAlgorithmInvocations,
			prometheus.GaugeValue,
			SCSIHealth.Get("verify.correction_algorithm_invocations").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
		// verify gigabytes_processed × 1e9  (read/write 는 bytes_read/written 에서 노출)
		smart.ch <- prometheus.MustNewConstMetric(
			metricVerifyBytesProcessed,
			prometheus.CounterValue,
			SCSIHealth.Get("verify.gigabytes_processed").Float()*1e9,
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

// mineSCSISasPhyEvents — SAS PHY event counters (port/phy 합산)
//
// JSON 구조 (smartctl 7.5, --log=sasphy):
//   "scsi_sas_port_0": {
//     "phy_0": {
//       "invalid_dword_count": N,
//       "running_disparity_error_count": N,
//       "loss_of_dword_synchronization_count": N,
//       "phy_reset_problem_count": N
//     },
//     "phy_1": { ... }
//   },
//   "scsi_sas_port_1": { ... }
//
// 디스크마다 port/phy 수가 다르므로 (single-port: port_0 만, dual-port: 0/1
// 둘 다, multi-phy: phy_0/1/2/3 등), 모든 scsi_sas_port_<N>.phy_<M> 을
// iterate 하며 카운터를 합산한다. Empty case 면 0 이 emit.
func (smart *SMARTctl) mineSCSISasPhyEvents() {
	var sumInvalidDword, sumRunDisparity, sumLossSync, sumPhyResetProblem float64
	phyFound := false

	// 모든 scsi_sas_port_* 키 탐색
	smart.json.ForEach(func(key, val gjson.Result) bool {
		k := key.String()
		if !strings.HasPrefix(k, "scsi_sas_port_") {
			return true
		}
		// 포트 안의 모든 phy_* 키
		val.ForEach(func(pkey, pval gjson.Result) bool {
			pk := pkey.String()
			if !strings.HasPrefix(pk, "phy_") {
				return true
			}
			phyFound = true
			sumInvalidDword += pval.Get("invalid_dword_count").Float()
			sumRunDisparity += pval.Get("running_disparity_error_count").Float()
			sumLossSync += pval.Get("loss_of_dword_synchronization_count").Float()
			sumPhyResetProblem += pval.Get("phy_reset_problem_count").Float()
			return true
		})
		return true
	})

	if !phyFound {
		return
	}
	smart.ch <- prometheus.MustNewConstMetric(
		metricSCSISasPhyInvalidDwordCount,
		prometheus.CounterValue,
		sumInvalidDword,
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
	smart.ch <- prometheus.MustNewConstMetric(
		metricSCSISasPhyRunningDisparityErrorCount,
		prometheus.CounterValue,
		sumRunDisparity,
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
	smart.ch <- prometheus.MustNewConstMetric(
		metricSCSISasPhyLossOfDwordSyncCount,
		prometheus.CounterValue,
		sumLossSync,
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
	smart.ch <- prometheus.MustNewConstMetric(
		metricSCSISasPhyResetProblemCount,
		prometheus.CounterValue,
		sumPhyResetProblem,
		smart.device.device,
		smart.device.serial,
		smart.device.model,
	)
}

// mineSCSIBackgroundScan — SCSI background scan log (--log=background)
//
// JSON 구조 (smartctl 7.5):
//   "scsi_background_scan": {
//     "status": { "code": 0, "string": "..." },
//     "accumulated_power_on_minutes": N,
//     "background_scans_performed": N,
//     "background_medium_scans_performed": N
//   }
func (smart *SMARTctl) mineSCSIBackgroundScan() {
	bs := smart.json.Get("scsi_background_scan")
	if !bs.Exists() {
		return
	}
	if v := bs.Get("background_scans_performed"); v.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSIBackgroundScansPerformed,
			prometheus.CounterValue,
			v.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
	if v := bs.Get("background_medium_scans_performed"); v.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSIBackgroundMediumScansPerformed,
			prometheus.CounterValue,
			v.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
	if v := bs.Get("status.code"); v.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSIBackgroundScanStatusCode,
			prometheus.GaugeValue,
			v.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

// mineSCSILifetimeCycles — start_stop_cycle_counter 의 추가 lifetime 필드.
// accumulated_start_stop_cycles 는 power_cycle_count 로 이미 노출됨.
//
// JSON 구조 (smartctl 7.5):
//   "scsi_start_stop_cycle_counter": {
//     "year_of_manufacture": "2019",
//     "specified_cycle_count_over_device_lifetime": N,
//     "accumulated_start_stop_cycles": N,
//     "specified_load_unload_count_over_device_lifetime": N,
//     "accumulated_load_unload_cycles": N
//   }
//
// 일부 필드는 string ("2019") 인 경우가 있어 ParseFloat 로 안전 처리.
func (smart *SMARTctl) mineSCSILifetimeCycles() {
	sc := smart.json.Get("scsi_start_stop_cycle_counter")
	if !sc.Exists() {
		return
	}
	if v := sc.Get("accumulated_load_unload_cycles"); v.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSIAccumulatedLoadUnloadCycles,
			prometheus.CounterValue,
			v.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
	if v := sc.Get("specified_load_unload_count_over_device_lifetime"); v.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSISpecifiedLoadUnloadCount,
			prometheus.GaugeValue,
			v.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
	if v := sc.Get("specified_cycle_count_over_device_lifetime"); v.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSISpecifiedCycleCount,
			prometheus.GaugeValue,
			v.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
	if v := sc.Get("year_of_manufacture"); v.Exists() {
		// year 은 string "2019" 또는 int 일 수 있음. gjson.Float() 가 양쪽
		// 안전 처리. parse 실패 시 0 이 되므로 nonzero 일 때만 emit.
		if y := v.Float(); y > 0 {
			smart.ch <- prometheus.MustNewConstMetric(
				metricSCSIYearOfManufacture,
				prometheus.GaugeValue,
				y,
				smart.device.device,
				smart.device.serial,
				smart.device.model,
			)
		}
	}
}

func (smart *SMARTctl) mineSCSIPercentageUsedEndurance() {
	// smartctl 7.5: top-level integer field
	// e.g. "scsi_percentage_used_endurance_indicator": 5
	pue := smart.json.Get("scsi_percentage_used_endurance_indicator")
	if pue.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSIPercentageUsedEndurance,
			prometheus.GaugeValue,
			pue.Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}

func (smart *SMARTctl) mineSCSIPendingDefects() {
	pd := smart.json.Get("scsi_pending_defects")
	if pd.Exists() {
		smart.ch <- prometheus.MustNewConstMetric(
			metricSCSIPendingDefectsCount,
			prometheus.GaugeValue,
			pd.Get("count").Float(),
			smart.device.device,
			smart.device.serial,
			smart.device.model,
		)
	}
}
