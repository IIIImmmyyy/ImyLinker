if(SYSTEM.Darwin)
  add_executable(darwin_example
    main.cc
    darwin_common_api.cc
  )

  target_link_libraries(darwin_example
    ${dobby_output_name}
  )
endif()

if(SYSTEM.Android)
  add_executable(android_example
    main.cc
    android_common_api.cc
    )

  target_link_libraries(android_example
    aaa
    )
endif()