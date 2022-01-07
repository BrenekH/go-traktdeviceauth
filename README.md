# Go Trakt Device Auth Library

[![GoDoc](https://pkg.go.dev/badge/github.com/BrenekH/go-traktdeviceauth)](https://pkg.go.dev/github.com/BrenekH/go-traktdeviceauth)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/BrenekH/go-traktdeviceauth?label=version)
[![License](https://img.shields.io/github/license/BrenekH/go-traktdeviceauth)](https://github.com/BrenekH/go-traktdeviceauth/tree/master/LICENSE)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/BrenekH/go-traktdeviceauth)

A Go library to allow an end user to authorize a third-party Trakt application access to their account using the [device method](https://trakt.docs.apiary.io/#reference/authentication-devices/generate-new-device-codes).

## Conventions

### Client ID and Client Secret

Throughout the library, the Client ID and Client Secret are used to tell Trakt which app is requesting access.
These values are found in the [dashboard for the app on Trakt's website](https://trakt.tv/oauth/applications), as shown in the image below.

![Client ID and Client Secret on the Trakt Application Dashboard](/images/client-id-secret-dashboard.png)

### Context Functions

Many functions in this library have context counterparts which allow a custom [context.Context](https://pkg.go.dev/context#Context) to be used.
If you don't know what all this means, you'll probably be fine sticking with the non-context versions.

## Usage

As suggested by the [official API docs](https://trakt.docs.apiary.io/#reference/authentication-devices/generate-new-device-codes), a device and user code pair must be generated as the first step using [GenerateNewCode](https://pkg.go.dev/github.com/BrenekH/go-traktdeviceauth#GenerateNewCode).
Next, the user needs to directed to the returned verification url and instructed to enter the user code into the website.
Finally, [PollForAuthToken](https://pkg.go.dev/github.com/BrenekH/go-traktdeviceauth#GenerateNewCode) is used to wait for the user to complete authentication or the code to expire.

Trakt recommends that the `AccessToken` and `RefreshToken` be saved in permanent storage so that the user doesn't need to log in every time your program starts.

## License

This project is licensed under the Apache 2.0 license, a copy of which can be found in [LICENSE](LICENSE).
