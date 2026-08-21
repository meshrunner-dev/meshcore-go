package meshcore

import (
	"encoding/hex"
	"errors"
	"math"
	"testing"
)

func floatVal(t *testing.T, r LPPReading) float64 {
	t.Helper()
	v, ok := r.Value.(float64)
	if !ok {
		t.Fatalf("reading type %d: value %T is not float64", r.Type, r.Value)
	}
	return v
}

func mustAdd(t *testing.T, e *LPPEncoder, r LPPReading) {
	t.Helper()
	if err := e.Add(r); err != nil {
		t.Fatalf("Add %+v: %v", r, err)
	}
}

// A repeater's own telemetry blob: channel 1 voltage 4.20 V, channel 1
// temperature 23.5 °C — the shape simple_repeater emits.
func TestLPPRepeaterTelemetry(t *testing.T) {
	e := NewLPPEncoder()
	mustAdd(t, e, LPPReading{Channel: 1, Type: LPPVoltage, Value: 4.20})
	mustAdd(t, e, LPPReading{Channel: 1, Type: LPPTemperature, Value: 23.5})
	// Voltage 4.20*100=420=0x01A4; temp 23.5*10=235=0x00EB.
	if got := hex.EncodeToString(e.Bytes()); got != "017401a4016700eb" {
		t.Fatalf("bytes = %s, want 017401a4016700eb", got)
	}
	r, err := LPPDecode(e.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 2 || r[0].Type != LPPVoltage || floatVal(t, r[0]) != 4.20 {
		t.Errorf("voltage: %+v", r[0])
	}
	if r[1].Type != LPPTemperature || floatVal(t, r[1]) != 23.5 {
		t.Errorf("temperature: %+v", r[1])
	}
}

func TestLPPRoundTripScalars(t *testing.T) {
	e := NewLPPEncoder()
	readings := []LPPReading{
		{Channel: 2, Type: LPPRelativeHumidity, Value: 55.5},
		{Channel: 3, Type: LPPCurrent, Value: 1.234},
		{Channel: 4, Type: LPPBarometricPressure, Value: 1013.2},
		{Channel: 5, Type: LPPDirection, Value: 270.0},
		{Channel: 6, Type: LPPEnergy, Value: 12.345},
		{Channel: 7, Type: LPPUnixTime, Value: 1_700_000_000.0},
	}
	for _, r := range readings {
		mustAdd(t, e, r)
	}
	got, err := LPPDecode(e.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range readings {
		w, _ := want.Value.(float64)
		if v := floatVal(t, got[i]); math.Abs(v-w) > 1e-6 {
			t.Errorf("reading %d = %v, want %v", i, v, w)
		}
	}
}

func TestLPPGPSRoundTrip(t *testing.T) {
	gps := LPPGPSValue{Latitude: 48.8584, Longitude: 2.2945, Altitude: 35.0}
	e := NewLPPEncoder()
	mustAdd(t, e, LPPReading{Channel: 1, Type: LPPGPS, Value: gps})
	r, err := LPPDecode(e.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r[0].Value.(LPPGPSValue)
	if !ok {
		t.Fatalf("value is %T", r[0].Value)
	}
	if math.Abs(got.Latitude-gps.Latitude) > 1e-4 ||
		math.Abs(got.Longitude-gps.Longitude) > 1e-4 ||
		math.Abs(got.Altitude-gps.Altitude) > 1e-2 {
		t.Errorf("GPS = %+v, want %+v", got, gps)
	}
}

func TestLPPNegativeValues(t *testing.T) {
	e := NewLPPEncoder()
	mustAdd(t, e, LPPReading{Channel: 1, Type: LPPTemperature, Value: -12.3})
	mustAdd(t, e, LPPReading{Channel: 2, Type: LPPGPS, Value: LPPGPSValue{Latitude: -33.8688, Longitude: 151.2093, Altitude: -5}})
	r, err := LPPDecode(e.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if floatVal(t, r[0]) != -12.3 {
		t.Errorf("negative temp = %v", r[0].Value)
	}
	gps, ok := r[1].Value.(LPPGPSValue)
	if !ok {
		t.Fatalf("value is %T", r[1].Value)
	}
	if math.Abs(gps.Latitude-(-33.8688)) > 1e-4 || math.Abs(gps.Altitude-(-5)) > 1e-2 {
		t.Errorf("negative GPS = %+v", gps)
	}
}

func TestLPPValueTypeMismatch(t *testing.T) {
	e := NewLPPEncoder()
	if err := e.Add(LPPReading{Channel: 1, Type: LPPGPS, Value: 3.14}); !errors.Is(err, ErrBadLPPValue) {
		t.Errorf("GPS with a float value: %v", err)
	}
	if err := e.Add(LPPReading{Channel: 1, Type: LPPPolyline, Value: nil}); !errors.Is(err, ErrBadLPP) {
		t.Errorf("polyline encode should be unsupported: %v", err)
	}
}

func TestLPPDecodeErrors(t *testing.T) {
	if _, err := LPPDecode([]byte{0x01}); !errors.Is(err, ErrBadLPP) {
		t.Error("truncated header accepted")
	}
	if _, err := LPPDecode([]byte{0x01, 0x67}); !errors.Is(err, ErrBadLPP) {
		t.Error("truncated payload accepted")
	}
	if _, err := LPPDecode([]byte{0x01, 0xFE, 0x00}); !errors.Is(err, ErrBadLPP) {
		t.Error("unknown type accepted")
	}
	r, err := LPPDecode([]byte{0x01, LPPTemperature, 0x00, 0xEB, 0x00, 0xFF, 0xFF})
	if err != nil || len(r) != 1 {
		t.Errorf("end marker: %d readings, err %v", len(r), err)
	}
}

func TestLPPPolylineDecode(t *testing.T) {
	lat0 := encodeInt24(488584) // 48.8584 * 10000
	lon0 := encodeInt24(22945)  // 2.2945 * 10000
	payload := []byte{8, 227, lat0[0], lat0[1], lat0[2], lon0[0], lon0[1], lon0[2]}
	buf := append([]byte{1, LPPPolyline}, payload...)
	r, err := LPPDecode(buf)
	if err != nil {
		t.Fatal(err)
	}
	pl, ok := r[0].Value.(LPPPolylineValue)
	if !ok {
		t.Fatalf("value is %T", r[0].Value)
	}
	if len(pl.Coordinates) != 1 || math.Abs(pl.Coordinates[0].Latitude-48.8584) > 1e-4 {
		t.Errorf("polyline = %+v", pl)
	}
}
