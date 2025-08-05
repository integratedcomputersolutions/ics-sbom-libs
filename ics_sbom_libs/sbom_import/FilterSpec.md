<!--
   SPDX-FileCopyrightText: 2025 ICS inc.
   SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ISCBOM Filter Spec

## Intro

The `icsbom` application takes in SBOM input files, looks for the packages in the SBOM files, and will produce a report 
of all the CVEs for each package that it finds.  Unfortunately, not all SBOMs are complete or have accurate information
To fix this we use a filter file to adjust the information coming from the SBOMs packages.  This document describes the
filter format used when processing the SBOM files.

## File Format

The base form of the filter file is a JSON document and it follows this basic form:

```json
{
  "substitutions" : {
    "packageName": { 
      "action": { 
        "actionProperty": "propertyValue"
      },
      ...
    }
  }
  "exclusions" : [
  ]
}
```

Below is an example of renaming a simple package:

```json
{
  "substitutions" : {
    "libcurl3": {"rename":  "libcurl"}
  }
}
```

In the example, we see that if the package `libcurl3` is found, that the action `rename` should be applied to the package
renaming it to `libcurl`.

## Substitutions

The "substitutions" key in the file will describe all of the package substitution actions that will need to be taken.  These
substitutions can modify the package list or modify the CPE strings for a package in the package list.  Below are descriptions
of each package actions and cpe actions that can be applied through the "substitutions" filters. 

### Package Actions

The table below describes the different actions that can be applied to packages within the SBOM.

<table>
<tr><td>Action</td><td>Parameter</td><td>Description</td></tr>
<tr>
<td>

`"rename"`

</td>
<td>

`"<new_name>"`

</td>
<td>

This action renames a package from what is found in the SBOM file to what is listed in `<new_name>`  as its replacement.

```json
{
  "libcurl3": {"rename":  "libcurl"}
}
```

</td>
</tr>
<tr>
<td>

`"remove"`

</td>
<td>""</td>
<td>
Removes the package from the SBOM package list.  It will not appear in the resulting VEX report.

```json
{
  "zlib" : {
    "remove" : ""
  }
}
```

</td>
</tr>
<tr>
<td>

`"duplicate"`

</td>
<td>

`{<actions>}`

</td>
<td>

This action duplicates the SBOM package, but requires `<actions>` to know what to do with either the original or the duplicate.

```json
{ 
  "qtbase": {
    "duplicate": {
      "rename": "qt"
    },
    "sub_cpe": {
      "product": {
        "orig": "qt", 
        "new": "<name>"
      }
    }
  }
}
```
</td>
</tr>
</table>

### CPE Actions:

The following table describes the actions that can be applied to the CPE string for a package within the SBOM.  The parts
that are currently available to be changed in the CPE string are `"vendor"`, `"product"`, and `"version"`. These will be
placed in the CPE string, `"cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*"`, for the package the action is being
applied too. 

When setting the `"product"` and `"version"` of the cpe filter, you can use `"<name>"` and `"<version>"` for those 
key/value pairs respectively.  `"<name>"` will automatically fill in the cpe `"product"` value with the package name.  
`"<version>"` will automatically use the package version from the SBOM package description to fill in the version number
of the string.  You can use any other strings for the `"product"` and `"version"` fields as well.

<table>
<tr><td>Action</td><td>Parameter</td><td>Description</td></tr>
<tr>
<td>

`"add_cpe"`

</td>
<td>

```json
{
  "vendor": "<cpe_vendor>", 
  "product": "<cpe_package_name>", 
  "version": "<cpe_package_version>"
}
```

</td>
<td>

Adds a new CPE string to the package.  This command should be used with all three CPE string parts: `"vendor"`, 
`"product"`, and `"version"`. The examples below are two filters that we use.  As can be seen, for `"perl"` we are using
the SBOM name and version, and for `"libflac8"` we give it a specific product name.  

```json
{
  "libflac8": { 
    "add_cpe": {
      "vendor": "flac_project", 
      "product": "flac", 
      "version": "<version>"
    }
  },
  "perl": {
    "add_cpe": {
      "vendor": "perl",
      "product": "<name>",
      "version": "<version>"
    }
  }
}
```

</td>
</tr>
<tr>
<td>

`"sub_cpe"`

</td>
<td>

```json 
{
  "<cpe_part>": { 
    "orig": "<cpe_part_match_criteria>", 
    "new": "<replacement_value>"
  },
  ...
}
```

</td>
<td>

The `"sub_cpe"` action modifies in-place any CPE string found in the SBOM package its filtering.  The substitutions can
be stacked into the same action call making multiple modifications.  Each step uses the same format.  When specifying
the `"orig"` matching criteria, a glob (`"*"`) can be used to tell the filter to replace the `"<cpe_part>"` in all CPE
strings found for that package.  

**NOTE:** There is currently no support for partial matching.

```json
{
  "flac": {
    "sub_cpe": {
      "vendor": {
        "orig": "*",
        "new": "flac_project"
      },
      "product": {
        "orig": "libflac",
        "new": "<name>"
      }
    }
  }
}
```


</td>
</tr>
<tr>
<td>

`"rem_cpe"`

</td>
<td>

```json
{
  "<cpe_part>": "<cpe_part_match_criteria>"
}
```

</td>
<td>

This action removes the CPE string that matches the CPE part criteria from the SBOM package.

```json
{
  "curl": {
    "rem_cpe": {
      "product": "libcurl"
    }
  }
}
```

</td>
</tr>
</table>

## Exclusions 

The "exclusions" key holds a list of file patterns that can be used to filter out different SBOM input files.  This was 
done to help reduce the number of files that had to be loaded and to make sure we were loading things that were not 
neccessary.  Some specific examples of this were excluding SPDX file that dealt only with source packages or example
packages.

```json
{
  "exclusions" : [
    "-src",
    "-examples",
  ]
}
```

**Note:** The "exclusions" list is formatted just like a Python list.

## Current Filter

Below, is the current filter used as default in the ICS_SBOM_LIBS.

```json
{
  "substitutions" : {
    "qtbase": {"duplicate": {"rename": "qt"}, "sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtsvg": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtdeclarative": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtgraphicaleffects": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtmultimedia": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtquickcontrols": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtquickcontrols2": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtserialport": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qttools": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtvirtualkeyboard": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtwebsockets": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "qtxmlpatterns": {"sub_cpe": {"product": {"orig": "qt", "new": "<name>"}}},
    "flex": {"add_cpe": {"vendor": "westes", "product": "<name>", "version": "<version>"}},
    "dbus": {"duplicate": {"rename": "libdbus", "sub_cpe": {"product": {"orig": "dbus", "new": "<name>"}}}},
    "flac": {
      "sub_cpe": {
        "vendor": {"orig": "*", "new": "flac_project"},
        "product": {"orig": "libflac", "new": "<name>"},
      }
    },
    "bzip2": {"add_cpe": {"vendor": "bzip", "product": "compress-raw-bzip2", "version": "<version>"}},
    "libflac++6": {"add_cpe": {"vendor": "flac_project", "product": "flac", "version": "<version>"}},
    "libflac8": {"add_cpe": {"vendor": "flac_project", "product": "flac", "version": "<version>"}},
    "curl": {
      "duplicate": {"rename": "libcurl", "rem_cpe": {"product": "curl"}},
      "rem_cpe": {"product": "libcurl"},
    },
    "libcurl3": {"rename": "libcurl"},
    "libcurl4": {"rename": "libcurl"},
    "expat": {
      "duplicate": {"rename": "libexpat", "rem_cpe": {"product": "expat"}},
      "rem_cpe": {"product": "libexpat"},
    },
    "file": {"add_cpe": {"vendor": "file_project", "product": "<name>", "version": "<version>"}},
    "perl": {"add_cpe": {"vendor": "perl", "product": "<name>", "version": "<version>"}},
  },

  "exclusions" : [
            "-doc",
            "-dev",
            "-dbg",
            "locale",
            "-ptest",
            "-tests",
            "-examples",
            "-mkspecs",
            "-staticdev",
            "qttranslations",
            "packagegroup",
            "glibc-gconv",
            "glibc-charmap",
            "tzdata-",
            "-completion",
            "-data",
            "-src",
            "-native",
            "-cross-",
            "-source-",
            "-headers",
            "index.json",
  ],
}
```
