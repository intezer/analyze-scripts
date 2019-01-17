# Intezer Analyze SDK
Basic scripts of Intezer Analyze API 2.0

Currently the following scripts are available:

- [Analyze by file](analyze_by_file.py)
- [Analyze by hash](analyze_by_hash.py): Supports SHA256, SHA1 and MD5
- [Get Latest Analysis](get_latest_analysis.py): Gets the latest analysis for the give hash available for your account
- [Cluster Directory](cluster_directory.py): Create a graph based on code reuse between all the files in a specific directory. The script prints basic graph using `matplotlib`, for example:
![Example Graph](https://raw.githubusercontent.com/intezer/analyze-sdk/master/artwork/Figure_1.png)

More information on how to obtain API access to could be found in our [blog post](https://www.intezer.com/blog-api-intezer-analyze-community/)
