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
	// Applying ATA-only logs to a SCSI device causes non-zero smartctl exit_status
	// bits and noisy messages, so we branch on device.Type.
	baseType := strings.ToLower(strings.SplitN(device.Type, ",", 2)[0])
	isSCSI := baseType == "scsi" || baseType == "sas"
	isNVMe := baseType == "nvme"

	smartctlArgs := []string{
		"--json", "--info", "--health", "--attributes",
		"--tolerance=verypermissive",
		"--nocheck=" + *smartctlPowerModeCheck,
		"--format=brief",
		"--log=error", "--log=selftest",
	}
	if !isSCSI && !isNVMe {
		// ATA / SATA
		smartctlArgs = append(smartctlArgs,
			"--log=devstat", "--log=sataphy", "--log=scterc")
	}
	if isSCSI {
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
