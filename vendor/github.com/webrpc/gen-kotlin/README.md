# gen-kotlin

This repo contains the templates used by the `webrpc-gen` cli to code-generate
webrpc Kotlin client code.

This generator, from a webrpc schema/design file will code-generate:

1. Client -- a Kotlin client (via Ktor and Moshi) to speak to a webrpc server using the
provided schema. This client is compatible with any webrpc server language (ie. Go, nodejs, etc.).

## Dependencies

In order to support communication with server, dependencies to few libraries must be provided.
This is a dependency of the generated code, so you must add it to your project.

Add this to `build.gradle.kts`:
```kotlin
val coroutinesVersion = "1.7.3"
implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")

val moshiVersion = "1.15.0"
implementation("com.squareup.moshi:moshi-kotlin:$moshiVersion")
implementation("com.squareup.moshi:moshi-kotlin-codegen:$moshiVersion")
implementation("com.squareup.moshi:moshi-adapters:$moshiVersion")

val ktorVersion = "2.3.7"
implementation("io.ktor:ktor-client-core:$ktorVersion")
implementation("io.ktor:ktor-client-logging:$ktorVersion")
implementation("io.ktor:ktor-client-cio-jvm:$ktorVersion")

// implementation("ch.qos.logback:logback-classic:1.4.14") // Optional for logging
```

## Usage

```
webrpc-gen -schema=example.ridl -target=kotlin -client -out=./example.gen.kt
```

or 

```
webrpc-gen -schema=example.ridl -target=github.com/webrpc/gen-kotlin@v0.14.0 -client -out=./example.gen.kt
```

or

```
webrpc-gen -schema=example.ridl -target=./local-templates-on-disk -client -out=./example.gen.kt
```

As you can see, the `-target` supports default `kotlin`, any git URI, or a local folder :)

### Set custom template variables
Change any of the following values by passing `-option="Value"` CLI flag to `webrpc-gen`.

| webrpc-gen -option              | Description                | Default value              |
|---------------------------------|----------------------------|----------------------------|
| `-client`                       | generate client code       | unset (`false`)            |
| `-packageName=%package name%`   | define package name        | `io.webrpc.client`         |

## LICENSE

[MIT LICENSE](./LICENSE)