package codec

import "github.com/google/gopacket"

// SerializeLayers serializes layers to byte array.
func SerializeLayers(layers ...gopacket.SerializableLayer) ([]byte, error) {
	// Recalculate checksum and length
	options := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	buffer := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buffer, options, layers...)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
