# Paycek

This is an official package for the [Paycek crypto payment processor](https://paycek.io). The documentation provided in code explains only minor implementation details.

For in depth information about endpoints, fields and more, read our [API Documentation](https://paycek.io/api/docs).

## Quick Start

### Installation

Add dependency with maven.

```xml
<dependency>
    <groupId>io.paycek</groupId>
    <artifactId>paycek</artifactId>
    <version>1.1.0</version>
</dependency>
```

### Initialization

Under account settings you’ll find your API key and secret. Initialize a paycek instance.

```
import io.paycek.Paycek;

Paycek paycek = new Paycek("<apiKey>", "<apiSecret>");
```

### Usage


#### Get payment
```
Map<String, Object> response = paycek.getPayment("<paymentCode>");
```

#### Open payment
```
Map<String, Object> optionalFields = new HashMap<>();
optionalFields.put("location_id", "<locationId>");

Map<String, Object> response = paycek.openPayment("<profileCode>", "<dstAmount>", optionalFields);
```