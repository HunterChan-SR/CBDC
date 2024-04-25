rootPath=$(cd "$(dirname "$0")"; pwd)


export ANDROID_OUT=./jniLibs
export ANDROID_SDK=${HOME}/Library/Android/sdk
export NDK_BIN=${ANDROID_SDK}/ndk/25.1.8937393/toolchains/llvm/prebuilt/darwin-x86_64/bin
export LIBNAME=libgnark.so
export GOSRC=./main.go
# export CGO_LDFLAGS="-static"
#macOS:
# export CGO_ENABLED=1
# export GOOS=darwin
# export GOARCH=arm64
# export CC=gcc
# export CXX=g++
# go build -buildmode=c-shared -o ./macOS/libgnark.so ${GOSRC}



# android-armv7a:
export CGO_ENABLED=1
export GOOS=android
export GOARCH=arm
export GOARM=7 
export CC=${NDK_BIN}/armv7a-linux-androideabi26-clang
go build -buildmode=c-shared -o ${ANDROID_OUT}/armeabi-v7a/${LIBNAME} ${GOSRC}


# android-arm64:
export CGO_ENABLED=1 
export GOOS=android 
export GOARCH=arm64 
export CC=${NDK_BIN}/aarch64-linux-android26-clang 
go build -buildmode=c-shared -o ${ANDROID_OUT}/arm64-v8a/${LIBNAME} ${GOSRC}

# # android-x86:
export CGO_ENABLED=1 
export GOOS=android 
export GOARCH=386 
export CC=${NDK_BIN}/i686-linux-android26-clang 
go build -buildmode=c-shared -o ${ANDROID_OUT}/x86/${LIBNAME} ${GOSRC}

# # android-x86_64:
export CGO_ENABLED=1 
export GOOS=android 
export GOARCH=amd64 
export CC=${NDK_BIN}/x86_64-linux-android26-clang 
go build -buildmode=c-shared -o ${ANDROID_OUT}/x86_64/${LIBNAME} ${GOSRC}



# # IOSarm:
# export CFLAGS="-arch arm64 -miphoneos-version-min=9.0 -isysroot "$(xcrun -sdk iphoneos --show-sdk-path) 
# export CGO_LDFLAGS="-arch arm64 -miphoneos-version-min=9.0 -isysroot "$(xcrun -sdk iphoneos --show-sdk-path)  
# export CGO_ENABLED=1 
# export GOARCH=arm64
# export GOOS=darwin 
# export CC="clang $CFLAGS $CGO_LDFLAGS" 
# go build -tags ios -ldflags=-w -trimpath -v -o ./IOS/libgnark-arm64.so -buildmode c-shared ${GOSRC}
# # IOSx86:
# export CFLAGS="-arch x86_64 -miphoneos-version-min=9.0 -isysroot "$(xcrun -sdk iphonesimulator --show-sdk-path) 
# export CGO_LDFLAGS="-arch x86_64 -miphoneos-version-min=9.0 -isysroot "$(xcrun -sdk iphonesimulator --show-sdk-path) 
# export CGO_ENABLED=1
# export GOARCH=amd64
# export GOOS=darwin
# export CC="clang $CFLAGS $CGO_LDFLAGS"
# go build -tags ios -ldflags=-w -trimpath -v -o ./IOS/libgnark-x86_64.so -buildmode c-shared ${GOSRC}


# #编译android版本功能
# rootPath=$(cd "$(dirname "$0")"; pwd)
# rm -f ${rootPath}/libtest.h
# rm -f ${rootPath}/libtest.so
 
# export GOARCH=arm64
# export GOOS=android
# export CGO_ENABLED=1
# export CC=/Users/hunterchan/Library/Android/sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang
# go build -tags macos -ldflags=-w -trimpath -v -o "libtest.so" -buildmode c-shared


# export ANDROID_OUT=./jniLibs
# export ANDROID_SDK=$(HOME)/Library/Android/sdk
# export NDK_BIN=$(ANDROID_SDK)/ndk/26.2.11394342/toolchains/llvm/prebuilt/darwin-x86_64/bin

# android-armv7a:
# 	export CGO_ENABLED=1 \
# 	export GOOS=android \
# 	export GOARCH=arm \
# 	export GOARM=7 \
# 	export CC=$(NDK_BIN)/armv7a-linux-androideabi21-clang \
# 	go build -buildmode=c-shared -o $(ANDROID_OUT)/armeabi-v7a/libhello.so ./hello

# android-arm64:
# 	export CGO_ENABLED=1 \
# 	export GOOS=android \
# 	export GOARCH=arm64 \
# 	export CC=$(NDK_BIN)/aarch64-linux-android21-clang \
# 	go build -buildmode=c-shared -o $(ANDROID_OUT)/arm64-v8a/libhello.so ./hello

# android-x86:
# 	export CGO_ENABLED=1 \
# 	export GOOS=android \
# 	export GOARCH=386 \
# 	export CC=$(NDK_BIN)/i686-linux-android21-clang \
# 	go build -buildmode=c-shared -o $(ANDROID_OUT)/x86/libhello.so ./hello

# android-x86_64:
# 	export CGO_ENABLED=1 \
# 	export GOOS=android \
# 	export GOARCH=amd64 \
# 	export CC=$(NDK_BIN)/x86_64-linux-android21-clang \
# 	go build -buildmode=c-shared -o $(ANDROID_OUT)/x86_64/libhello.so ./hello

# android: android-armv7a android-arm64 android-x86 android-x86_64