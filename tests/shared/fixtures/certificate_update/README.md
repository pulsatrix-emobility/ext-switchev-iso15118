# CertificateUpdateReq fragment oracle

`fragment.hex` is the 63-byte schema-informed EXI fragment emitted by
local-controller commit `b79e77620a2ecd820f32172b9ad7b5c2ed9b2613`, using
`ExiFragmentEncoder.iso2Message()` and its ISO 15118-2 schemas. It was generated
independently of josev and its vendored codec. The test compares every byte.

The certificate fields contain the literal ASCII strings `leaf`, `sub2`, and
`sub1`; these are not certificates. The identity is a placeholder. No key
material is needed or retained. `GenerateUpdateFragment.java` defines the entire
input, also constructed in `test_certificate_update_fragment.py`.

To reproduce with that LC checkout compiled and its runtime dependencies on
`LC_CLASSPATH` (including `target/classes`), use Java 25:

```sh
java -cp "$LC_CLASSPATH" GenerateUpdateFragment.java > fragment.hex
```

The old josev codec encodes this element with the wrong namespace/document
mode. ISO 15118-2 [V2G2-768] §7.9.2.4.2 requires schema-informed EXI fragments for
signed parts. Adding the update element to the codec's fragment list makes the
output match this independent oracle.
