# SIAT
The SIAT has two part : Monitor and Analyzer. 

## Monitor

Monitor is based on the Android 4.3. After deployed Taintdroid in Android 4.3 system, you should replace the the file [base] in path "\frameworks\base\", file [io] in path  "/libcore/luni/src/main/java/java/io/" and cover Taint.java.

You should generate the image and run it in the device or virtual device after replacing files.

Running the apps in new system "Monitor", you will get the running logs. 

## Analyzer
After get the log file, you could use the command to analyze the logs:
```
python analyzer.py logs_file.txt apk_path
```

## apk
We have uploaded some datasets in this folder with a description file.

