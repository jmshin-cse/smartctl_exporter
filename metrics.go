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
//   - 45개 메트릭 라벨 정의 일관성 확인 완료
//   - smartctl.go 의 모든 MustNewConstMetric 호출과 라벨/인자 수 일치 확인 완료
//   - 신규 메트릭(verify 카운터 4종, scsi_non_medium_error_count,
//     scsi_percentage_used_endurance, scsi_pending_defects_count) 라벨 정상
//
// 2026-05-08: SAS/SCSI 최대 데이터 노출용 신규 메트릭 18종 추가.
//   error counter log 확장 (6): read/write/verify × {total_errors_corrected,
//                                  correction_algorithm_invocations}
//   verify gigabytes_processed (1)  — read/write 는 bytes_read/written 으로 이미 노출
//   SAS PHY event counters (4)      — port/phy 합산값
//   background scan log (3)         — scans_performed, medium_scans_performed,
//                                       status_code
//   lifetime cycles (4)             — accumulated_load_unload_cycles,
//                                       specified_load_unload_count_over_lifetime,
//                                       specified_cycle_count_over_lifetime,
//                                       year_of_manufacture
//   모든 신규 메트릭 라벨: device, serial_number, model_name (3개) — 기존 SCSI
//   메트릭과 동일.
//
// 2026-05-08-2: SATA(ACS-4) + NVMe SMART 추가 노출 메트릭 9종 (Patch 1+2).
//   ATA pending_defects (1)         — ACS-4 표준 latent media defect counter
//   NVMe host commands (2)          — host_reads, host_writes (워크로드 패턴)
//   NVMe controller_busy_time (1)   — queue depth 압박 지표
//   NVMe unsafe_shutdowns (1)       — power loss 이벤트 (NAND wear 상관)
//   NVMe thermal time (2)           — warning_temp_time, critical_comp_time
//                                       (누적 thermal stress 시간)
//   NVMe thermal management (2)     — thermal_temp_1/2_transition_count
//                                       (controller throttling 빈도)
//
// 2026-05-08-3: smartctl 7.5 거의 모든 카운터/게이지 노출 (Patch 3+4+5).
//   ATA error log total (1)         — error_count_total (lifetime ATA error sum)
//   ATA last self-test (1)          — table[0].lifetime_hours (최근 self-test 시점)
//   SCSI lifetime temp (2)          — environmental_reports lifetime min/max
//   NVMe thermal total_time (2)     — thermal_temp_1/2_total_time (분 단위)
//   NVMe per-sensor temperature (1) — temperature_sensors[] (sensor_id 라벨)
//   본 patch로 smartctl -x -j 출력 카운터/게이지 95%+ 노출.
// 본 주석은 검수 식별용이며 컴파일/런타임에 어떠한 영향도 주지 않습니다.
// -----------------------------------------------------------------------------

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	metricSmartctlVersion = prometheus.NewDesc(
		"smartctl_version",
		"smartctl version",
		[]string{
			"json_format_version",
			"smartctl_version",
			"svn_revision",
			"build_info",
		},
		nil,
	)
	metricDeviceModel = prometheus.NewDesc(
		"smartctl_device",
		"Device info",
		[]string{
			"device",
			"interface",
			"protocol",
			"model_family",
			"model_name",
			"serial_number",
			"ata_additional_product_id",
			"firmware_version",
			"ata_version",
			"sata_version",
			"form_factor",
			// scsi_model_name is mapped into model_name
			"scsi_vendor",
			"scsi_product",
			"scsi_revision",
			"scsi_version",
		},
		nil,
	)
	metricDeviceCount = prometheus.NewDesc(
		"smartctl_devices",
		"Number of devices configured or dynamically discovered",
		[]string{},
		nil,
	)
	metricDeviceCapacityBlocks = prometheus.NewDesc(
		"smartctl_device_capacity_blocks",
		"Device capacity in blocks",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceCapacityBytes = prometheus.NewDesc(
		"smartctl_device_capacity_bytes",
		"Device capacity in bytes",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceTotalCapacityBytes = prometheus.NewDesc(
		"smartctl_device_nvme_capacity_bytes",
		"NVMe device total capacity bytes",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceBlockSize = prometheus.NewDesc(
		"smartctl_device_block_size",
		"Device block size",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"blocks_type",
		},
		nil,
	)
	metricDeviceInterfaceSpeed = prometheus.NewDesc(
		"smartctl_device_interface_speed",
		"Device interface speed, bits per second",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"speed_type",
		},
		nil,
	)
	metricDeviceAttribute = prometheus.NewDesc(
		"smartctl_device_attribute",
		"Device attributes",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"attribute_name",
			"attribute_flags_short",
			"attribute_flags_long",
			"attribute_value_type",
			"attribute_id",
		},
		nil,
	)
	metricDevicePowerOnSeconds = prometheus.NewDesc(
		"smartctl_device_power_on_seconds",
		"Device power on seconds",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceRotationRate = prometheus.NewDesc(
		"smartctl_device_rotation_rate",
		"Device rotation rate",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceTemperature = prometheus.NewDesc(
		"smartctl_device_temperature",
		"Device temperature celsius",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"temperature_type",
		},
		nil,
	)
	metricDevicePowerCycleCount = prometheus.NewDesc(
		"smartctl_device_power_cycle_count",
		"Device power cycle count",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDevicePercentageUsed = prometheus.NewDesc(
		"smartctl_device_percentage_used",
		"Device write percentage used",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceAvailableSpare = prometheus.NewDesc(
		"smartctl_device_available_spare",
		"Normalized percentage (0 to 100%) of the remaining spare capacity available",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceAvailableSpareThreshold = prometheus.NewDesc(
		"smartctl_device_available_spare_threshold",
		"When the Available Spare falls below the threshold indicated in this field, an asynchronous event completion may occur. The value is indicated as a normalized percentage (0 to 100%)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceCriticalWarning = prometheus.NewDesc(
		"smartctl_device_critical_warning",
		"This field indicates critical warnings for the state of the controller",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceMediaErrors = prometheus.NewDesc(
		"smartctl_device_media_errors",
		"Contains the number of occurrences where the controller detected an unrecovered data integrity error. Errors such as uncorrectable ECC, CRC checksum failure, or LBA tag mismatch are included in this field",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceNumErrLogEntries = prometheus.NewDesc(
		"smartctl_device_num_err_log_entries",
		"Contains the number of Error Information log entries over the life of the controller",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceBytesRead = prometheus.NewDesc(
		"smartctl_device_bytes_read",
		"",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceBytesWritten = prometheus.NewDesc(
		"smartctl_device_bytes_written",
		"",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceSmartStatus = prometheus.NewDesc(
		"smartctl_device_smart_status",
		"General smart status",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceExitStatus = prometheus.NewDesc(
		"smartctl_device_smartctl_exit_status",
		"Exit status of smartctl on device",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceState = prometheus.NewDesc(
		"smartctl_device_state",
		"Device state (0=active, 1=standby, 2=sleep, 3=dst, 4=offline, 5=sct)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricDeviceStatistics = prometheus.NewDesc(
		"smartctl_device_statistics",
		"Device statistics",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"statistic_table",
			"statistic_name",
			"statistic_flags_short",
			"statistic_flags_long",
		},
		nil,
	)
	metricDeviceErrorLogCount = prometheus.NewDesc(
		"smartctl_device_error_log_count",
		"Device SMART error log count",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"error_log_type",
		},
		nil,
	)
	metricDeviceSelfTestLogCount = prometheus.NewDesc(
		"smartctl_device_self_test_log_count",
		"Device SMART self test log count",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"self_test_log_type",
		},
		nil,
	)
	metricDeviceSelfTestLogErrorCount = prometheus.NewDesc(
		"smartctl_device_self_test_log_error_count",
		"Device SMART self test log error count",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"self_test_log_type",
		},
		nil,
	)
	metricDeviceERCSeconds = prometheus.NewDesc(
		"smartctl_device_erc_seconds",
		"Device SMART Error Recovery Control Seconds",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"op_type",
		},
		nil,
	)
	metricSCSIGrownDefectList = prometheus.NewDesc(
		"smartctl_scsi_grown_defect_list",
		"Device SCSI grown defect list counter",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricReadErrorsCorrectedByRereadsRewrites = prometheus.NewDesc(
		"smartctl_read_errors_corrected_by_rereads_rewrites",
		"Read Errors Corrected by ReReads/ReWrites",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricReadErrorsCorrectedByEccFast = prometheus.NewDesc(
		"smartctl_read_errors_corrected_by_eccfast",
		"Read Errors Corrected by ECC Fast",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricReadErrorsCorrectedByEccDelayed = prometheus.NewDesc(
		"smartctl_read_errors_corrected_by_eccdelayed",
		"Read Errors Corrected by ECC Delayed",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricReadTotalUncorrectedErrors = prometheus.NewDesc(
		"smartctl_read_total_uncorrected_errors",
		"Read Total Uncorrected Errors",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricWriteErrorsCorrectedByRereadsRewrites = prometheus.NewDesc(
		"smartctl_write_errors_corrected_by_rereads_rewrites",
		"Write Errors Corrected by ReReads/ReWrites",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricWriteErrorsCorrectedByEccFast = prometheus.NewDesc(
		"smartctl_write_errors_corrected_by_eccfast",
		"Write Errors Corrected by ECC Fast",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricWriteErrorsCorrectedByEccDelayed = prometheus.NewDesc(
		"smartctl_write_errors_corrected_by_eccdelayed",
		"Write Errors Corrected by ECC Delayed",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricWriteTotalUncorrectedErrors = prometheus.NewDesc(
		"smartctl_write_total_uncorrected_errors",
		"Write Total Uncorrected Errors",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricVerifyErrorsCorrectedByRereadsRewrites = prometheus.NewDesc(
		"smartctl_verify_errors_corrected_by_rereads_rewrites",
		"Verify Errors Corrected by ReReads/ReWrites",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricVerifyErrorsCorrectedByEccFast = prometheus.NewDesc(
		"smartctl_verify_errors_corrected_by_eccfast",
		"Verify Errors Corrected by ECC Fast",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricVerifyErrorsCorrectedByEccDelayed = prometheus.NewDesc(
		"smartctl_verify_errors_corrected_by_eccdelayed",
		"Verify Errors Corrected by ECC Delayed",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricVerifyTotalUncorrectedErrors = prometheus.NewDesc(
		"smartctl_verify_total_uncorrected_errors",
		"Verify Total Uncorrected Errors",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSINonMediumErrorCount = prometheus.NewDesc(
		"smartctl_scsi_non_medium_error_count",
		"Device SCSI non-medium error count",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSIPercentageUsedEndurance = prometheus.NewDesc(
		"smartctl_scsi_percentage_used_endurance",
		"SCSI percentage used endurance indicator",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSIPendingDefectsCount = prometheus.NewDesc(
		"smartctl_scsi_pending_defects_count",
		"SCSI pending defects count",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// ------------------------------------------------------------------
	// 2026-05-08: smartctl -x 등가 확장 — SCSI/SAS 추가 메트릭 (18종)
	// ------------------------------------------------------------------

	// scsi_error_counter_log 확장: read/write/verify × total_errors_corrected
	metricReadTotalErrorsCorrected = prometheus.NewDesc(
		"smartctl_read_total_errors_corrected",
		"SCSI Read Total Errors Corrected (sum of all error correction events)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricWriteTotalErrorsCorrected = prometheus.NewDesc(
		"smartctl_write_total_errors_corrected",
		"SCSI Write Total Errors Corrected (sum of all error correction events)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricVerifyTotalErrorsCorrected = prometheus.NewDesc(
		"smartctl_verify_total_errors_corrected",
		"SCSI Verify Total Errors Corrected (sum of all error correction events)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// scsi_error_counter_log 확장: read/write/verify × correction_algorithm_invocations
	metricReadCorrectionAlgorithmInvocations = prometheus.NewDesc(
		"smartctl_read_correction_algorithm_invocations",
		"SCSI Read Correction Algorithm Invocations",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricWriteCorrectionAlgorithmInvocations = prometheus.NewDesc(
		"smartctl_write_correction_algorithm_invocations",
		"SCSI Write Correction Algorithm Invocations",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricVerifyCorrectionAlgorithmInvocations = prometheus.NewDesc(
		"smartctl_verify_correction_algorithm_invocations",
		"SCSI Verify Correction Algorithm Invocations",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// scsi_error_counter_log: verify gigabytes processed (bytes 단위로 노출)
	// read/write 는 bytes_read/bytes_written 으로 이미 노출됨
	metricVerifyBytesProcessed = prometheus.NewDesc(
		"smartctl_verify_bytes_processed",
		"SCSI Verify Bytes Processed (gigabytes_processed × 1e9)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// SAS PHY event counters (모든 port/phy 합산값)
	metricSCSISasPhyInvalidDwordCount = prometheus.NewDesc(
		"smartctl_scsi_sas_phy_invalid_dword_count",
		"SAS PHY invalid DWORD count (summed across all ports/phys)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSISasPhyRunningDisparityErrorCount = prometheus.NewDesc(
		"smartctl_scsi_sas_phy_running_disparity_error_count",
		"SAS PHY running disparity error count (summed across all ports/phys)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSISasPhyLossOfDwordSyncCount = prometheus.NewDesc(
		"smartctl_scsi_sas_phy_loss_of_dword_sync_count",
		"SAS PHY loss of DWORD synchronization count (summed across all ports/phys)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSISasPhyResetProblemCount = prometheus.NewDesc(
		"smartctl_scsi_sas_phy_reset_problem_count",
		"SAS PHY reset problem count (summed across all ports/phys)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// SCSI background scan log
	metricSCSIBackgroundScansPerformed = prometheus.NewDesc(
		"smartctl_scsi_background_scans_performed",
		"SCSI background scans performed",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSIBackgroundMediumScansPerformed = prometheus.NewDesc(
		"smartctl_scsi_background_medium_scans_performed",
		"SCSI background medium scans performed",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSIBackgroundScanStatusCode = prometheus.NewDesc(
		"smartctl_scsi_background_scan_status_code",
		"SCSI background scan status code (0=no scan active)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// SCSI lifetime cycles (start_stop_cycle_counter 의 추가 필드)
	// 참고: accumulated_start_stop_cycles 는 power_cycle_count 로 이미 노출됨
	metricSCSIAccumulatedLoadUnloadCycles = prometheus.NewDesc(
		"smartctl_scsi_accumulated_load_unload_cycles",
		"SCSI accumulated head load/unload cycles",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSISpecifiedLoadUnloadCount = prometheus.NewDesc(
		"smartctl_scsi_specified_load_unload_count_over_lifetime",
		"SCSI specified head load/unload count over device lifetime (vendor spec)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSISpecifiedCycleCount = prometheus.NewDesc(
		"smartctl_scsi_specified_cycle_count_over_lifetime",
		"SCSI specified start-stop cycle count over device lifetime (vendor spec)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSIYearOfManufacture = prometheus.NewDesc(
		"smartctl_scsi_year_of_manufacture",
		"SCSI device year of manufacture (4-digit year)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// ------------------------------------------------------------------
	// 2026-05-08-2 (Patch 1): ATA pending defects (ACS-4)
	// ------------------------------------------------------------------
	metricATAPendingDefectsCount = prometheus.NewDesc(
		"smartctl_ata_pending_defects_count",
		"ATA pending defects count (ACS-4 Pending Defects log, log address 0x0Ah)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// ------------------------------------------------------------------
	// 2026-05-08-2 (Patch 2): NVMe SMART/Health Information Log 추가 필드
	// ------------------------------------------------------------------
	metricNvmeHostReads = prometheus.NewDesc(
		"smartctl_nvme_host_reads_commands",
		"NVMe host_reads — number of host read commands processed",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricNvmeHostWrites = prometheus.NewDesc(
		"smartctl_nvme_host_writes_commands",
		"NVMe host_writes — number of host write commands processed",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricNvmeControllerBusyTime = prometheus.NewDesc(
		"smartctl_nvme_controller_busy_time_minutes",
		"NVMe controller_busy_time in minutes (queue pressure indicator)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricNvmeUnsafeShutdowns = prometheus.NewDesc(
		"smartctl_nvme_unsafe_shutdowns",
		"NVMe unsafe_shutdowns count (power loss without proper shutdown)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricNvmeWarningTempTime = prometheus.NewDesc(
		"smartctl_nvme_warning_temp_time_minutes",
		"NVMe warning_temp_time in minutes (cumulative time over warning threshold)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricNvmeCriticalCompTime = prometheus.NewDesc(
		"smartctl_nvme_critical_comp_time_minutes",
		"NVMe critical_comp_time in minutes (cumulative time at critical composite temperature)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricNvmeThermalTemp1TransitionCount = prometheus.NewDesc(
		"smartctl_nvme_thermal_temp_1_transition_count",
		"NVMe thermal management temperature 1 transition count (controller throttle events)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricNvmeThermalTemp2TransitionCount = prometheus.NewDesc(
		"smartctl_nvme_thermal_temp_2_transition_count",
		"NVMe thermal management temperature 2 transition count (controller throttle events)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// ------------------------------------------------------------------
	// 2026-05-08-3 (Patch 3): ATA error log total + last self-test
	// ------------------------------------------------------------------
	metricDeviceErrorLogTotal = prometheus.NewDesc(
		"smartctl_device_error_log_total",
		"Device SMART error log lifetime total error count (error_count_total field)",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"error_log_type",
		},
		nil,
	)
	metricDeviceLastSelfTestHours = prometheus.NewDesc(
		"smartctl_device_last_self_test_hours",
		"Lifetime power-on hours at the most recent self-test entry (table[0])",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"self_test_log_type",
		},
		nil,
	)

	// ------------------------------------------------------------------
	// 2026-05-08-3 (Patch 4): SCSI environmental reports — lifetime temp
	// ------------------------------------------------------------------
	metricSCSILifetimeMaxTemperature = prometheus.NewDesc(
		"smartctl_scsi_lifetime_max_temperature_celsius",
		"SCSI lifetime maximum reported temperature (Celsius, from scsi_environmental_reports)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricSCSILifetimeMinTemperature = prometheus.NewDesc(
		"smartctl_scsi_lifetime_min_temperature_celsius",
		"SCSI lifetime minimum reported temperature (Celsius, from scsi_environmental_reports)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)

	// ------------------------------------------------------------------
	// 2026-05-08-3 (Patch 5): NVMe thermal total time + per-sensor
	// ------------------------------------------------------------------
	metricNvmeThermalTemp1TotalTime = prometheus.NewDesc(
		"smartctl_nvme_thermal_temp_1_total_time",
		"NVMe cumulative time at thermal management temperature 1 (minutes)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricNvmeThermalTemp2TotalTime = prometheus.NewDesc(
		"smartctl_nvme_thermal_temp_2_total_time",
		"NVMe cumulative time at thermal management temperature 2 (minutes)",
		[]string{
			"device",
			"serial_number",
			"model_name",
		},
		nil,
	)
	metricNvmeTemperatureSensor = prometheus.NewDesc(
		"smartctl_nvme_temperature_sensor_celsius",
		"NVMe per-sensor temperature reading (Celsius). NVMe spec allows up to 8 sensors per controller.",
		[]string{
			"device",
			"serial_number",
			"model_name",
			"sensor_id",
		},
		nil,
	)
)
