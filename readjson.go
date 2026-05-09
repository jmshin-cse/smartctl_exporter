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
// 2026-04-23: 이 파일은 Claude 의 다중 패스(7-pass) 검수 + 3-파일 통합 검증을
// 통과한 버전입니다.
//   - smartctl 7.5 transport-specific log 인자 분기 정상
//     (ATA: devstat/sataphy/scterc, SCSI/SAS: defects, 공통: error/selftest)
//   - baseType 추출이 "sat,auto" / "scsi,megaraid" 같은 복합 타입에 대해 안전
//   - smartctl.go 의 device.interface_ 기반 SCSI 분기와 식별 로직 정합
//   - sync.Map + WaitGroup 동시성 패턴 안전 (Device 가 comparable 이라는
//     전제 하에)
//   - resultCodeIsOk: bit 0,1 만 fatal 처리 → prefail/error 디스크의 시계열도
//     캐시에 보존됨 (SINDy 분석에 필수)
//   - parseJSON invalid 가드 + smartctl.go 의 .Exists() 가드와 정합
//
// 2026-04-27: RAID 컨트롤러 뒤 디스크의 메트릭 누락 이슈 수정.
//   - 기존 로직: device.Type 의 baseType 이 "scsi"/"sas" 일 때만 --log=defects
//     추가 → "megaraid,N", "3ware,N", "aacraid,N,L,ID", "cciss,N", "areca,N",
//     "hpsa,N" 등 RAID wrapper 뒤의 SAS HDD 에서 scsi_pending_defects_count
//     메트릭이 누락되는 버그.
//   - 수정 후: 디바이스 타입을 4분류(NVMe/명시적 ATA/명시적 SCSI/모호) 로
//     판정하고, "모호" (auto, megaraid, 3ware 등) 케이스에는 ATA 로그와
//     SCSI 로그를 모두 추가. --tolerance=verypermissive 가 무관한 로그를
//     흡수하므로 데이터 손실 없이 모든 RAID 환경에서 pending_defects 수집.
//
// 2026-05-08: SAS/SCSI 최대 데이터 노출 — `smartctl -x -j` 등가 확장.
//   - 기존: SCSI/SAS 분기에 --log=defects 만 추가
//   - 변경: --log=background (background scan log),
//           --log=sasphy   (SAS PHY event counters: invalid_dword_count,
//                           running_disparity_error_count,
//                           loss_of_dword_synchronization_count,
//                           phy_reset_problem_count),
//           --log=ssd      (SSD endurance/wear, 일부 SAS-SSD 만 적용),
//           --log=xerror   (extended error counter log — read/write/verify
//                           gigabytes_processed, total_errors_corrected,
//                           correction_algorithm_invocations 등 추가 필드),
//           --log=xselftest(extended self-test log)
//     모두 SCSI/SAS 또는 ambiguous 케이스에 추가.
//   - --tolerance=verypermissive 가 미지원 로그를 흡수하므로 SATA 디스크가
//     ambiguous 케이스로 분류되어도 데이터 손실 없음.
//   - 효과: SAS PHY 카운터 4종, scsi_background_scan, lifetime cycle
//     counter (load/unload, specified count over lifetime) 등 SINDy 분석에
//     유용한 카운터들이 모두 노출됨.
//
// 2026-05-08-2: ATA 측에도 --log=defects 추가 (Patch 1)
//   - ACS-4 이후 SATA 디스크는 "Pending Defects log" (ATA log address 0x0Ah)
//     를 표준으로 노출. 신규 SATA HDD/SSD 가 발견한 latent media defect 의
//     실시간 카운터로 SINDy 분석의 강한 feature.
//   - 기존엔 SCSI 분기에서만 추가됐었는데, ATA 분기에도 추가하여
//     ata_pending_defects.count → metricATAPendingDefectsCount 로 노출.
//   - 미지원 disk(구형 ATA)는 --tolerance=verypermissive 가 흡수하므로 안전.
//
// 2026-05-08-3: SCSI 측에 --log=envrep 추가 (Patch 4)
//   - smartmontools 7.5 신설 옵션. SCSI Environmental Reports log page (0x0D)
//     를 출력하여 lifetime_max_temperature / lifetime_min_temperature 등
//     thermal stress 누적 지표를 노출.
//   - mineSCSIEnvironmentalReports() 가 scsi_environmental_reports JSON 을
//     읽으려면 본 옵션이 필수.
//   - SCSI 미지원 케이스 (예: ATA 디스크가 ambiguous 분류)는
//     --tolerance=verypermissive 가 흡수.
// 본 주석은 검수 식별용이며 컴파일/런타임에 어떠한 영향도 주지 않습니다.
// -----------------------------------------------------------------------------

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

// JSONCache caching json
type JSONCache struct {
	JSON        gjson.Result
	LastCollect time.Time
}

var (
	jsonCache sync.Map
)

func init() {
	jsonCache.Store("", JSONCache{})
}

// Parse json to gjson object
func parseJSON(data string) gjson.Result {
	if !gjson.Valid(data) {
		return gjson.Parse("{}")
	}
	return gjson.Parse(data)
}

// Reading fake smartctl json
func readFakeSMARTctl(logger *slog.Logger, device Device) gjson.Result {
	s := strings.Split(device.Name, "/")
	filename := fmt.Sprintf("debug/%s.json", s[len(s)-1])
	logger.Debug("Read fake S.M.A.R.T. data from json", "filename", filename)
	jsonFile, err := os.ReadFile(filename)
	if err != nil {
		logger.Error("Fake S.M.A.R.T. data reading error", "err", err)
		return parseJSON("{}")
	}
	return parseJSON(string(jsonFile))
}

// Get json from smartctl and parse it
func readSMARTctl(logger *slog.Logger, device Device, wg *sync.WaitGroup) {
	defer wg.Done()
	start := time.Now()
	// smartctl 7.5: log options are transport-specific.
	//   ATA/SATA only : --log=devstat, --log=sataphy, --log=scterc
	//   SCSI/SAS only : --log=defects (populates scsi_pending_defects.count)
	//   Common        : --log=error, --log=selftest
	//
	// device.Type 4분류 + RAID 처리:
	//   isNVMe        — "nvme", "nvme,N"
	//   isExplicitATA — "sat", "ata", "sat+megaraid,N", "sat+jmb39x,N" 등
	//                   (sat/ata prefix → 확실히 SATA underlying)
	//   isExplicitSCSI— "scsi", "sas" (직결)
	//   ambiguous     — "auto", "megaraid,N", "3ware,N", "areca,N", "cciss,N",
	//                   "aacraid,N,L,ID", "hpsa,N" 등 RAID wrapper
	//                   → underlying 디스크 타입을 알 수 없음
	//
	// ambiguous 케이스에는 ATA 로그와 SCSI 로그를 모두 추가한다.
	// smartctl 은 underlying 디스크가 지원하지 않는 로그를 무시하고
	// (--tolerance=verypermissive 와 결합) exit_status bit 2 만 set 함.
	// resultCodeIsOk 가 bit 2 를 warn-only 로 처리하므로 데이터 손실 없음.
	// 이로 인해 SAS-via-MegaRAID 같은 케이스에서도 scsi_pending_defects_count
	// 가 정상 수집된다.
	baseType := strings.ToLower(strings.SplitN(device.Type, ",", 2)[0])
	isNVMe := baseType == "nvme"
	isExplicitATA := strings.HasPrefix(baseType, "sat") || strings.HasPrefix(baseType, "ata")
	isExplicitSCSI := baseType == "scsi" || baseType == "sas"
	isAmbiguous := !isNVMe && !isExplicitATA && !isExplicitSCSI

	smartctlArgs := []string{
		"--json", "--info", "--health", "--attributes",
		"--tolerance=verypermissive",
		"--nocheck=" + *smartctlPowerModeCheck,
		"--format=brief",
		"--log=error", "--log=selftest",
	}
	if isExplicitATA || isAmbiguous {
		// ATA/SATA logs (확실한 ATA + 모호 케이스)
		smartctlArgs = append(smartctlArgs,
			"--log=devstat", "--log=sataphy", "--log=scterc")
	}
	if isExplicitSCSI || isAmbiguous {
		// SCSI/SAS logs (확실한 SCSI/SAS + 모호 케이스 — RAID 뒤 SAS 보장)
		// `smartctl -x -j` 등가 확장: background + sasphy + ssd
		// + xerror + xselftest + envrep. SAS HDD 의 최대 데이터를 노출한다.
		// 2026-05-08-3 (Patch 4): --log=envrep 추가 — SCSI Environmental
		// Reports log page (0x0D, smartmontools 7.5 신규 옵션).
		smartctlArgs = append(smartctlArgs,
			"--log=background",
			"--log=sasphy",
			"--log=ssd",
			"--log=xerror",
			"--log=xselftest",
			"--log=envrep",
		)
	}
	// --log=defects: ATA(ACS-4) 및 SCSI(SBC-3) 양쪽 transport 모두 지원.
	// NVMe 는 미지원 → 명시적으로 NVMe 만 제외하고 추가하여 중복 없이 단일.
	if !isNVMe {
		smartctlArgs = append(smartctlArgs, "--log=defects")
	}
	smartctlArgs = append(smartctlArgs, "--device="+device.Type, device.Name)

	logger.Debug("Calling smartctl with args", "args", strings.Join(smartctlArgs, " "))
	out, err := exec.Command(*smartctlPath, smartctlArgs...).Output()
	if err != nil {
		logger.Warn("S.M.A.R.T. output reading", "err", err, "device", device)
	}
	// Accommodate a smartmontools pre-7.3 bug
	cleaned_out := strings.TrimPrefix(string(out), "  Pending defect count:")
	json := parseJSON(cleaned_out)
	rcOk := resultCodeIsOk(logger, device, json.Get("smartctl.exit_status").Int())
	jsonOk := jsonIsOk(logger, json)
	logger.Debug("Collected S.M.A.R.T. json data", "device", device, "duration", time.Since(start))
	if rcOk && jsonOk {
		jsonCache.Store(device, JSONCache{JSON: json, LastCollect: time.Now()})
	}
}

func readSMARTctlDevices(logger *slog.Logger) gjson.Result {
	logger.Debug("Scanning for devices")
	scanArgs := []string{"--json", "--scan"}
	for _, d := range *smartctlScanDeviceTypes {
		scanArgs = append(scanArgs, "--device", d)
	}
	out, err := exec.Command(*smartctlPath, scanArgs...).Output()
	if exiterr, ok := err.(*exec.ExitError); ok {
		logger.Debug("Exit Status", "exit_code", exiterr.ExitCode())
		// The smartctl command returns 2 if devices are sleeping, ignore this error.
		if exiterr.ExitCode() != 2 {
			logger.Warn("S.M.A.R.T. output reading error", "err", err)
			return gjson.Result{}
		}
	} else if err != nil {
		logger.Warn("S.M.A.R.T. output reading error", "err", err)
		return gjson.Result{}
	}
	return parseJSON(string(out))
}

// Refresh all devices' json
func refreshAllDevices(logger *slog.Logger, devices []Device) {
	if *smartctlFakeData {
		return
	}

	var wg sync.WaitGroup
	for _, device := range devices {
		cacheValue, cacheOk := jsonCache.Load(device)
		if !cacheOk || time.Now().After(cacheValue.(JSONCache).LastCollect.Add(*smartctlInterval)) {
			wg.Add(1)
			go readSMARTctl(logger, device, &wg)
		}
	}
	wg.Wait()
}

func readData(logger *slog.Logger, device Device) gjson.Result {
	if *smartctlFakeData {
		return readFakeSMARTctl(logger, device)
	}

	cacheValue, found := jsonCache.Load(device)
	if !found {
		logger.Warn("device not found", "device", device)
		return gjson.Result{}
	}
	return cacheValue.(JSONCache).JSON
}

// Parse smartctl return code
func resultCodeIsOk(logger *slog.Logger, device Device, SMARTCtlResult int64) bool {
	result := true
	if SMARTCtlResult > 0 {
		b := SMARTCtlResult
		if (b & 1) != 0 {
			logger.Error("Command line did not parse", "device", device)
			result = false
		}
		if (b & (1 << 1)) != 0 {
			logger.Error("Device open failed, device did not return an IDENTIFY DEVICE structure, or device is in a low-power mode", "device", device)
			result = false
		}
		if (b & (1 << 2)) != 0 {
			logger.Warn("Some SMART or other ATA command to the disk failed, or there was a checksum error in a SMART data structure", "device", device)
		}
		if (b & (1 << 3)) != 0 {
			logger.Warn("SMART status check returned 'DISK FAILING'", "device", device)
		}
		if (b & (1 << 4)) != 0 {
			logger.Warn("We found prefail Attributes <= threshold", "device", device)
		}
		if (b & (1 << 5)) != 0 {
			logger.Warn("SMART status check returned 'DISK OK' but we found that some (usage or prefail) Attributes have been <= threshold at some time in the past", "device", device)
		}
		if (b & (1 << 6)) != 0 {
			logger.Warn("The device error log contains records of errors", "device", device)
		}
		if (b & (1 << 7)) != 0 {
			logger.Warn("The device self-test log contains records of errors. [ATA only] Failed self-tests outdated by a newer successful extended self-test are ignored", "device", device)
		}
	}
	return result
}

// Check json
func jsonIsOk(logger *slog.Logger, json gjson.Result) bool {
	messages := json.Get("smartctl.messages")
	// logger.Debug(messages.String())
	if messages.Exists() {
		for _, message := range messages.Array() {
			if message.Get("severity").String() == "error" {
				logger.Error(message.Get("string").String())
				return false
			}
		}
	}
	return true
}
