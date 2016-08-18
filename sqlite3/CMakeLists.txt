add_definitions(
  -DSQLITE_ENABLE_COLUMN_METADATA
  -DSQLITE_ENABLE_API_ARMOR
  -DSQLITE_ENABLE_JSON1
  -DSQLITE_ENABLE_MEMORY_MANAGEMENT
  # Functionality disables
  -DSQLITE_DISABLE_LFS
  -DSQLITE_DISABLE_DIRSYNC
  -DSQLITE_DISABLE_FTS3_UNICODE
  -DSQLITE_DISABLE_FTS4_DEFERRED
  -DSQLITE_OMIT_AUTHORIZATION
  -DSQLITE_OMIT_DEPRECATED
  -DSQLITE_OMIT_SHARED_CACHE
  # Omitting the WAL will prevent database file access.
  #-DSQLITE_OMIT_WAL
  -DSQLITE_OMIT_LOOKASIDE
  -DSQLITE_ENABLE_DBSTAT_VTAB
)

if(WIN32)
  foreach(flag_var
          CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
          CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO)
    if(${flag_var} MATCHES "/MD")
      string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endif(${flag_var} MATCHES "/MD")
  endforeach(flag_var)
else()
  add_compile_options(
    -Wno-parentheses-equality
    -Wno-unused-value
  )
endif()

add_library(osquery_sqlite OBJECT sqlite3.c)
