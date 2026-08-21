package meshcore

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Cayenne LPP is the sensor-telemetry payload format MeshCore carries in
// its telemetry blobs (the reference firmware uses the ElectronicCats
// CayenneLPP library; even a repeater reports its battery voltage and
// MCU temperature this way). Each reading is [channel][type][value…],
// values big-endian; channel 0 ends the stream.
//
// This is a self-contained codec — no MeshCore crypto or framing — so it
// stays a pure protocol primitive. LPPDecode and LPPEncoder.Add are the
// two halves; a reading round-trips through both.

// LPP data types (ElectronicCats / IPSO codes).
const (
	LPPDigitalInput       byte = 0
	LPPDigitalOutput      byte = 1
	LPPAnalogInput        byte = 2
	LPPAnalogOutput       byte = 3
	LPPGenericSensor      byte = 100
	LPPLuminosity         byte = 101
	LPPPresence           byte = 102
	LPPTemperature        byte = 103
	LPPRelativeHumidity   byte = 104
	LPPAccelerometer      byte = 113
	LPPBarometricPressure byte = 115
	LPPVoltage            byte = 116
	LPPCurrent            byte = 117
	LPPFrequency          byte = 118
	LPPPercentage         byte = 120
	LPPAltitude           byte = 121
	LPPConcentration      byte = 125
	LPPPower              byte = 128
	LPPDistance           byte = 130
	LPPEnergy             byte = 131
	LPPDirection          byte = 132
	LPPUnixTime           byte = 133
	LPPGyrometer          byte = 134
	LPPColour             byte = 135
	LPPGPS                byte = 136
	LPPSwitch             byte = 142
	LPPPolyline           byte = 240
)

// Codec errors.
var (
	// ErrBadLPP reports a malformed Cayenne LPP buffer.
	ErrBadLPP = errors.New("meshcore: malformed Cayenne LPP")
	// ErrBadLPPValue reports a reading whose value does not match its type.
	ErrBadLPPValue = errors.New("meshcore: Cayenne LPP value type mismatch")
)

// polylineScale is the 0.0001° base resolution the polyline extension
// quantises against.
const polylineScale = 10000.0

// LPPReading is one decoded record. Value's concrete type follows Type:
// float64 for scalar types, or one of the LPP*Value structs.
type LPPReading struct {
	Channel byte
	Type    byte
	Value   any
}

// LPPGPSValue is latitude/longitude in degrees, altitude in metres.
type LPPGPSValue struct{ Latitude, Longitude, Altitude float64 }

// LPPAccelValue is acceleration in g on three axes.
type LPPAccelValue struct{ X, Y, Z float64 }

// LPPGyroValue is angular rate in °/s on three axes.
type LPPGyroValue struct{ X, Y, Z float64 }

// LPPColourValue is an 8-bit RGB triple.
type LPPColourValue struct{ R, G, B byte }

// LPPCoordinate is one polyline vertex, in degrees.
type LPPCoordinate struct{ Latitude, Longitude float64 }

// LPPPolylineValue is a decoded polyline: its factor byte and vertices.
type LPPPolylineValue struct {
	Factor      byte
	Coordinates []LPPCoordinate
}

// lppWidth returns the fixed value width for a type, or -1 for the
// variable-length polyline, or 0 for an unknown type.
func lppWidth(typ byte) int {
	switch typ {
	case LPPDigitalInput, LPPDigitalOutput, LPPPresence, LPPRelativeHumidity, LPPPercentage, LPPSwitch:
		return 1
	case LPPAnalogInput, LPPAnalogOutput, LPPLuminosity, LPPTemperature, LPPBarometricPressure,
		LPPVoltage, LPPCurrent, LPPAltitude, LPPConcentration, LPPPower, LPPDirection:
		return 2
	case LPPColour:
		return 3
	case LPPGenericSensor, LPPFrequency, LPPDistance, LPPEnergy, LPPUnixTime:
		return 4
	case LPPAccelerometer, LPPGyrometer:
		return 6
	case LPPGPS:
		return 9
	case LPPPolyline:
		return -1
	default:
		return 0
	}
}

// LPPDecode decodes a Cayenne LPP buffer into readings. Channel 0 marks
// the end of data; trailing bytes after it are ignored.
func LPPDecode(data []byte) ([]LPPReading, error) {
	var readings []LPPReading
	for i := 0; i < len(data); {
		if len(data)-i < 2 {
			return nil, fmt.Errorf("%w: truncated header", ErrBadLPP)
		}
		channel, typ := data[i], data[i+1]
		i += 2
		if channel == 0 { // end-of-data marker
			break
		}

		width := lppWidth(typ)
		switch width {
		case 0:
			return nil, fmt.Errorf("%w: unknown type %d", ErrBadLPP, typ)
		case -1: // polyline: the first payload byte is its total size
			if len(data)-i < 1 {
				return nil, fmt.Errorf("%w: polyline missing size", ErrBadLPP)
			}
			width = int(data[i])
			if width < 8 {
				return nil, fmt.Errorf("%w: polyline size %d below minimum 8", ErrBadLPP, width)
			}
		}
		if len(data)-i < width {
			return nil, fmt.Errorf("%w: type %d needs %d bytes, have %d", ErrBadLPP, typ, width, len(data)-i)
		}
		payload := data[i : i+width : i+width]
		i += width
		readings = append(readings, LPPReading{Channel: channel, Type: typ, Value: decodeLPPValue(typ, payload)})
	}
	return readings, nil
}

func decodeLPPValue(typ byte, p []byte) any {
	u16 := binary.BigEndian.Uint16
	i16 := func(b []byte) float64 { return float64(int16(binary.BigEndian.Uint16(b))) }
	switch typ {
	case LPPDigitalInput, LPPDigitalOutput, LPPPresence, LPPPercentage, LPPSwitch:
		return float64(p[0])
	case LPPRelativeHumidity:
		return float64(p[0]) / 2
	case LPPAnalogInput, LPPAnalogOutput:
		return i16(p) / 100
	case LPPLuminosity, LPPConcentration, LPPPower, LPPDirection:
		return float64(u16(p))
	case LPPTemperature:
		return i16(p) / 10
	case LPPBarometricPressure:
		return float64(u16(p)) / 10
	case LPPVoltage:
		return i16(p) / 100
	case LPPCurrent:
		return i16(p) / 1000
	case LPPAltitude:
		return i16(p)
	case LPPGenericSensor, LPPFrequency, LPPUnixTime:
		return float64(binary.BigEndian.Uint32(p))
	case LPPDistance, LPPEnergy:
		return float64(binary.BigEndian.Uint32(p)) / 1000
	case LPPAccelerometer:
		return LPPAccelValue{i16(p[0:2]) / 1000, i16(p[2:4]) / 1000, i16(p[4:6]) / 1000}
	case LPPGyrometer:
		return LPPGyroValue{i16(p[0:2]) / 100, i16(p[2:4]) / 100, i16(p[4:6]) / 100}
	case LPPColour:
		return LPPColourValue{p[0], p[1], p[2]}
	case LPPGPS:
		return LPPGPSValue{
			Latitude:  float64(decodeInt24(p[0:3])) / 10000,
			Longitude: float64(decodeInt24(p[3:6])) / 10000,
			Altitude:  float64(decodeInt24(p[6:9])) / 100,
		}
	case LPPPolyline:
		return decodePolyline(p)
	default:
		return nil
	}
}

// LPPEncoder builds a Cayenne LPP buffer one reading at a time. It is
// not safe for concurrent use; the zero value is ready to use.
type LPPEncoder struct {
	buf []byte
}

// NewLPPEncoder returns an empty encoder.
func NewLPPEncoder() *LPPEncoder { return &LPPEncoder{} }

// Bytes returns the encoded buffer, valid until the next Add or Reset.
func (e *LPPEncoder) Bytes() []byte { return e.buf }

// Reset empties the encoder for reuse.
func (e *LPPEncoder) Reset() { e.buf = e.buf[:0] }

// Add appends one reading, applying the type's scaling (the inverse of
// LPPDecode). Value must be a float64 for scalar types, or the matching
// LPP*Value struct for compound ones. Polyline encoding is not yet
// supported. Floats are rounded to the nearest wire unit.
func (e *LPPEncoder) Add(r LPPReading) error {
	width := lppWidth(r.Type)
	if width == 0 {
		return fmt.Errorf("%w: unknown type %d", ErrBadLPP, r.Type)
	}
	if r.Type == LPPPolyline {
		return fmt.Errorf("%w: polyline encoding is not implemented", ErrBadLPP)
	}
	e.buf = append(e.buf, r.Channel, r.Type)
	switch v := r.Value.(type) {
	case float64:
		return e.addScalar(r.Type, v)
	case LPPAccelValue:
		e.i16(v.X * 1000)
		e.i16(v.Y * 1000)
		e.i16(v.Z * 1000)
	case LPPGyroValue:
		e.i16(v.X * 100)
		e.i16(v.Y * 100)
		e.i16(v.Z * 100)
	case LPPColourValue:
		e.buf = append(e.buf, v.R, v.G, v.B)
	case LPPGPSValue:
		e.i24(v.Latitude * 10000)
		e.i24(v.Longitude * 10000)
		e.i24(v.Altitude * 100)
	default:
		return fmt.Errorf("%w: type %d got %T", ErrBadLPPValue, r.Type, r.Value)
	}
	return nil
}

// addScalar encodes a float64 value for a scalar type.
func (e *LPPEncoder) addScalar(typ byte, v float64) error {
	switch typ {
	case LPPDigitalInput, LPPDigitalOutput, LPPPresence, LPPPercentage, LPPSwitch:
		e.buf = append(e.buf, byte(round(v)))
	case LPPRelativeHumidity:
		e.buf = append(e.buf, byte(round(v*2)))
	case LPPAnalogInput, LPPAnalogOutput:
		e.i16(v * 100)
	case LPPLuminosity, LPPConcentration, LPPPower, LPPDirection:
		e.u16(uint16(round(v)))
	case LPPTemperature:
		e.i16(v * 10)
	case LPPBarometricPressure:
		e.u16(uint16(round(v * 10)))
	case LPPVoltage:
		e.i16(v * 100)
	case LPPCurrent:
		e.i16(v * 1000)
	case LPPAltitude:
		e.i16(v)
	case LPPGenericSensor, LPPFrequency, LPPUnixTime:
		e.u32(uint32(round(v)))
	case LPPDistance, LPPEnergy:
		e.u32(uint32(round(v * 1000)))
	default:
		return fmt.Errorf("%w: type %d needs a struct value, got float64", ErrBadLPPValue, typ)
	}
	return nil
}

func (e *LPPEncoder) u16(v uint16) { e.buf = binary.BigEndian.AppendUint16(e.buf, v) }
func (e *LPPEncoder) u32(v uint32) { e.buf = binary.BigEndian.AppendUint32(e.buf, v) }
func (e *LPPEncoder) i16(v float64) {
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(int16(round(v))))
}
func (e *LPPEncoder) i24(v float64) {
	b := encodeInt24(int32(round(v)))
	e.buf = append(e.buf, b[0], b[1], b[2])
}

func round(v float64) int64 {
	if v < 0 {
		return int64(v - 0.5)
	}
	return int64(v + 0.5)
}

func encodeInt24(v int32) [3]byte {
	u := uint32(v) & 0x00FFFFFF
	return [3]byte{byte(u >> 16), byte(u >> 8), byte(u)}
}

func decodeInt24(b []byte) int32 {
	v := int32(b[0])<<16 | int32(b[1])<<8 | int32(b[2])
	if v&0x00800000 != 0 {
		v |= ^int32(0x00FFFFFF) // sign-extend bit 23
	}
	return v
}

// polylineFactor maps a factor byte to its quantisation step
// (ElectronicCats getFactor): a small literal factor below 200, or one
// of the reserved precision codes at/above 227. Returns 0 for invalid.
func polylineFactor(f byte) float64 {
	switch {
	case f == 0:
		return 0
	case f < 200:
		return float64(f)
	default:
		steps := map[byte]float64{
			227: 1, 228: 2, 229: 5, 230: 10, 231: 20, 232: 50, 233: 100,
			234: 200, 235: 500, 236: 1000, 237: 2000, 238: 5000, 239: 10000,
		}
		return steps[f]
	}
}

// decodePolyline reconstructs a polyline from its payload (including the
// leading size byte). Deltas are two signed nibbles per byte, dLat low.
func decodePolyline(buf []byte) LPPPolylineValue {
	var out LPPPolylineValue
	if len(buf) < 7 {
		return out
	}
	out.Factor = buf[1]
	f := polylineFactor(buf[1])
	if f == 0 {
		return out
	}
	prevLat := int32(float64(decodeInt24(buf[2:5])) * f)
	prevLon := int32(float64(decodeInt24(buf[5:8])) * f)
	out.Coordinates = append(out.Coordinates,
		LPPCoordinate{float64(prevLat) / polylineScale, float64(prevLon) / polylineScale})
	for _, b := range buf[8:] {
		dLat, dLon := unpackDelta(b)
		prevLat += int32(float64(dLat) * f)
		prevLon += int32(float64(dLon) * f)
		out.Coordinates = append(out.Coordinates,
			LPPCoordinate{float64(prevLat) / polylineScale, float64(prevLon) / polylineScale})
	}
	return out
}

// unpackDelta splits a byte into two sign-extended 4-bit deltas, the
// latitude delta in the low nibble (matching the reference bitfield).
func unpackDelta(b byte) (int, int) {
	dLat := int(b & 0x0F)
	if dLat >= 8 {
		dLat -= 16
	}
	dLon := int(b>>4) & 0x0F
	if dLon >= 8 {
		dLon -= 16
	}
	return dLat, dLon
}
