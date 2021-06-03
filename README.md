# README

This project optimizes the `kdexts!FindObjectByName` to increase the speed of native object name resolution.

## Build

CMAKE is required to generate the whole project.

### Generate the solution

From the root directory, creates a `build` directory.
In this build directory :

```
cmake ..
```
	
###	Build

```   
cmake --build . --config Release
```` 

## Usage

You just have to load the module:
```
kd> .load WinDbgFastObj.dll
The kdexts!FindObjectByName is now optimized.
You can try !object, !drvobj, !devobj, !devstack...
```