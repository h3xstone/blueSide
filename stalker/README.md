## Description
stalker is a tool designed to help the investigator find all the files related to a person (here we will call it "victim") in a device.

## Features
- given a name the tool can search if the victim name appears in the filename or in the file content
- can make a transformation of the letters to look for the variants of the name
- can find all the photos and/or videos where people's faces appear
- given a reference image of the victim (**prefer one in which the face is in the foreground**), can find all photos and/or videos where the victim appears
- can save the results in json output file

## Versions
- **stalker:**  light version that can only find people in images/videos (*no comparison/recognition*). This was done in order to use the minimum possible of imports to make the tool more portable

- **stalker_full:**  full version that can find people in images/videos and can make a comparison to find only the photos/videos where the victim appears. This uses face recognition therefore requires to install more modules as well as being a little slower

## Installation
- if you want to use python version you have to download the script, the haarcascade file and manually install all the required modules. This can be nerve-racking because to have face recognition working you have to install *cmake* and *dlib* that in some cases can raise errors.
- if you want a standalone, ready-to-go version, you can download it directly from "the release", avoiding to manually install all dependencies, virtual-environment, etc. These versions are compiled for linux x64 and windows x64 and once downloaded they carry all the necessary packages inside.

## Extra
At the moment, for portability purposes, tool uses only CPU. However during tests i found that even with only 1 CPU the speed and the accuracy are acceptable.
The algorithm used is "hog" due to the use of CPU. In the future tool will be implemented with the possibility of choosing multiple CPUs and with the GPU support to make it faster and with the possibility of choosing the "cnn" algorithm to make the recognition more precise.