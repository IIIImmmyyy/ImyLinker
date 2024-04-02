//
// Created by PC5000 on 2024/3/26.
//

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <sys/param.h>
#include "linker.h"
#include "log.h"

#include "unordered_map"
//#include "elf.h"
#include "linker_phdr.h"
#include "linker_main.h"
#include "linker_block_allocator.h"
#include "../utils/ProcessRuntime.h"
#include "linker_namespaces.h"
#include "inttypes.h"

static LinkerTypeAllocator<soinfo> g_soinfo_allocator;

static LinkerTypeAllocator<LinkedListEntry<soinfo>> g_soinfo_links_allocator;

static LinkerTypeAllocator<android_namespace_t> g_namespace_allocator;
static LinkerTypeAllocator<LinkedListEntry<android_namespace_t>> g_namespace_list_allocator;

int get_application_target_sdk_version() {
    char prop_value[PROP_VALUE_MAX];
    __system_property_get("ro.build.version.sdk", prop_value);
    return atoi(prop_value);
}


void SoinfoListAllocator::free(LinkedListEntry<soinfo> *entry) {
    g_soinfo_links_allocator.free(entry);
}

LinkedListEntry<soinfo> *SoinfoListAllocator::alloc() {
    return g_soinfo_links_allocator.alloc();
}

LinkedListEntry<android_namespace_t> *NamespaceListAllocator::alloc() {
    return g_namespace_list_allocator.alloc();
}

void NamespaceListAllocator::free(LinkedListEntry<android_namespace_t> *entry) {
    g_namespace_list_allocator.free(entry);
}

static android_namespace_t *getDefaultNamespace() {
    //解析linker64
    const ElfModule &aModule = ProcessRuntime::GetTargetElfModule("linker64");
//    ElfReader()
    if (aModule.address != nullptr) {
        //temp add offset
        auto *pointer = reinterpret_cast<ToPointer *>((uint64_t) aModule.address +
                                                      0x120cc8); //read .data default namespaces offset this is temp code
        android_namespace_t *defaultNamespace = static_cast<android_namespace_t *>(pointer->pointer);
        return defaultNamespace;
    }
    return nullptr;
}

static android_namespace_t *get_caller_namespace(soinfo *caller) {
    return caller != nullptr ? caller->get_primary_namespace() : getDefaultNamespace();
}

/**
 *  从执行地址里找到是哪个so执行的
 * @param p
 * @return
 */
soinfo *find_containing_library(const void *p) {
    ElfW(Addr) address = reinterpret_cast<ElfW(Addr)>(untag_address(p));

    auto solist = linker_get_solist();
    for (auto it = solist.begin(); it != solist.end(); it++) {
        soinfo *si = static_cast<struct soinfo *>(*it);
        if (address < si->base || address - si->base >= si->size) {
            continue;
        }
        ElfW(Addr) vaddr = address - si->load_bias;
        //遍历程序头表的数量
        for (size_t i = 0; i != si->phnum; ++i) {
            const ElfW(Phdr) *phdr = &si->phdr[i];
            if (phdr->p_type != PT_LOAD) {
                continue;
            }
            if (vaddr >= phdr->p_vaddr && vaddr < phdr->p_vaddr + phdr->p_memsz) {
                return si;
            }
        }
    }
    return nullptr;
}

class ZipArchiveCache {
public:
    ZipArchiveCache() {}

    ~ZipArchiveCache();

//    bool get_or_open(const char* zip_path, ZipArchiveHandle* handle);
private:
    DISALLOW_COPY_AND_ASSIGN(ZipArchiveCache);

//    std::unordered_map<std::string, ZipArchiveHandle> cache_;
};

ZipArchiveCache::~ZipArchiveCache() {

}


// Each size has it's own allocator.
template<size_t size>
class SizeBasedAllocator {
public:
    static void *alloc() {
        return allocator_.alloc();
    }

    static void free(void *ptr) {
        allocator_.free(ptr);
    }

    static void purge() {
        allocator_.purge();
    }

private:
    static LinkerBlockAllocator allocator_;
};

template<size_t size>
LinkerBlockAllocator SizeBasedAllocator<size>::allocator_(size);

template<typename T>
class TypeBasedAllocator {
public:
    static T *alloc() {
        return reinterpret_cast<T *>(SizeBasedAllocator<sizeof(T)>::alloc());
    }

    static void free(T *ptr) {
        SizeBasedAllocator<sizeof(T)>::free(ptr);
    }

    static void purge() {
        SizeBasedAllocator<sizeof(T)>::purge();
    }
};

class LoadTask {
public:
    struct deleter_t {
        void operator()(LoadTask *t) {
            t->~LoadTask();
            TypeBasedAllocator<LoadTask>::free(t);
        }
    };

    static deleter_t deleter;

    // needed_by is NULL iff dlopen is called from memory that isn't part of any known soinfo.
    static LoadTask *create(const char *_Nonnull name, soinfo *_Nullable needed_by,
                            android_namespace_t *_Nonnull start_from,
                            std::unordered_map<const soinfo *, ElfReader> *_Nonnull readers_map) {
        LoadTask *ptr = TypeBasedAllocator<LoadTask>::alloc();
        return new(ptr) LoadTask(name, needed_by, start_from, readers_map);
    }

    const char *get_name() const {
        return name_;
    }

    soinfo *get_needed_by() const {
        return needed_by_;
    }

    soinfo *get_soinfo() const {
        return si_;
    }

    void set_soinfo(soinfo *si) {
        si_ = si;
    }

    off64_t get_file_offset() const {
        return file_offset_;
    }

    void set_file_offset(off64_t offset) {
        file_offset_ = offset;
    }

    int get_fd() const {
        return fd_;
    }

    void set_fd(int fd, bool assume_ownership) {
        if (fd_ != -1 && close_fd_) {
            close(fd_);
        }
        fd_ = fd;
        close_fd_ = assume_ownership;
    }

    const android_dlextinfo *get_extinfo() const {
        return extinfo_;
    }

    void set_extinfo(const android_dlextinfo *extinfo) {
        extinfo_ = extinfo;
    }

    bool is_dt_needed() const {
        return is_dt_needed_;
    }

    void set_dt_needed(bool is_dt_needed) {
        is_dt_needed_ = is_dt_needed;
    }

    // returns the namespace from where we need to start loading this.
    const android_namespace_t *get_start_from() const {
        return start_from_;
    }

    void remove_cached_elf_reader() {
        (*elf_readers_map_).erase(si_);
    }

    const ElfReader &get_elf_reader() const {
        return (*elf_readers_map_)[si_];
    }

    ElfReader &get_elf_reader() {
        return (*elf_readers_map_)[si_];
    }

    std::unordered_map<const soinfo *, ElfReader> *get_readers_map() {
        return elf_readers_map_;
    }

    bool read(const char *realpath, off64_t file_size) {
        ElfReader &elf_reader = get_elf_reader();
        return elf_reader.Read(realpath, fd_, file_offset_, file_size);
    }

    bool load(address_space_params *address_space) {
        ElfReader &elf_reader = get_elf_reader();

        if (!elf_reader.Load(address_space)) {
            return false;
        }

        si_->base = elf_reader.load_start();
        si_->size = elf_reader.load_size();
        si_->set_mapped_by_caller(elf_reader.is_mapped_by_caller());
        si_->load_bias = elf_reader.load_bias();
        si_->phnum = elf_reader.phdr_count();
        si_->phdr = elf_reader.loaded_phdr();
        si_->set_gap_start(elf_reader.gap_start());
        si_->set_gap_size(elf_reader.gap_size());

        return true;
    }

private:
    LoadTask(const char *name,
             soinfo *needed_by,
             android_namespace_t *start_from,
             std::unordered_map<const soinfo *, ElfReader> *readers_map)
            : name_(name), needed_by_(needed_by), si_(nullptr),
              fd_(-1), close_fd_(false), file_offset_(0), elf_readers_map_(readers_map),
              is_dt_needed_(false), start_from_(start_from) {}

    ~LoadTask() {
        if (fd_ != -1 && close_fd_) {
            close(fd_);
        }
    }

    const char *name_;
    soinfo *needed_by_;
    soinfo *si_;
    const android_dlextinfo *extinfo_;
    int fd_;
    bool close_fd_;
    off64_t file_offset_;
    std::unordered_map<const soinfo *, ElfReader> *elf_readers_map_;
    // TODO(dimitry): needed by workaround for http://b/26394120 (the exempt-list)
    bool is_dt_needed_;
    // END OF WORKAROUND
    const android_namespace_t *const start_from_;

    DISALLOW_IMPLICIT_CONSTRUCTORS(LoadTask);
};

LoadTask::deleter_t LoadTask::deleter;

template<typename T>
using linked_list_t = LinkedList<T, TypeBasedAllocator<LinkedListEntry<T>>>;

typedef linked_list_t<soinfo> SoinfoLinkedList;
typedef linked_list_t<const char> StringLinkedList;
typedef std::vector<LoadTask *> LoadTaskList;

soinfo *soinfo_alloc(android_namespace_t *ns, const char *name,
                     const struct stat *file_stat, off64_t file_offset,
                     uint32_t rtld_flags) {
    if (strlen(name) >= PATH_MAX) {
        LOGE("library name \"%s\" too long", name);
        return nullptr;
    }
    soinfo *si = new(g_soinfo_allocator.alloc()) soinfo(ns, name, file_stat,
                                                        file_offset, rtld_flags);

    //need add soinfo to main linker?
    si->generate_handle();
    ns->add_soinfo(si);
    return si;
}

static int open_library_at_path(ZipArchiveCache *zip_archive_cache,
                                const char *path, off64_t *file_offset,
                                std::string *realpath) {
    LOGI("open_library_at_path %s ", path);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd != -1) {
        *file_offset = 0;
        *realpath = path;
        return fd;
    }
    return fd;
}

static int open_library(android_namespace_t *ns,
                        ZipArchiveCache *zip_archive_cache,
                        const char *name, soinfo *needed_by,
                        off64_t *file_offset, std::string *realpath) {

    // If the name contains a slash, we should attempt to open it directly and not search the paths.
    if (strchr(name, '/') != nullptr) {
        return open_library_at_path(zip_archive_cache, name, file_offset, realpath);
    }
    return -1;
}

static void soinfo_free(soinfo *si) {
    if (si == nullptr) {
        return;
    }

    if (si->base != 0 && si->size != 0) {
        if (!si->is_mapped_by_caller()) {
            munmap(reinterpret_cast<void *>(si->base), si->size);
        } else {
            // remap the region as PROT_NONE, MAP_ANONYMOUS | MAP_NORESERVE
            mmap(reinterpret_cast<void *>(si->base), si->size, PROT_NONE,
                 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        }
    }

    if (si->has_min_version(6) && si->get_gap_size()) {
        munmap(reinterpret_cast<void *>(si->get_gap_start()), si->get_gap_size());
    }


//    if (!solist_remove_soinfo(si)) {
//        async_safe_fatal("soinfo=%p is not in soinfo_list (double unload?)", si);
//    }

    // clear links to/from si
    si->remove_all_links();

    si->~soinfo();
    g_soinfo_allocator.free(si);
}

template<typename F>
static void for_each_dt_needed(const ElfReader &elf_reader, F action) {
    for (const ElfW(Dyn) *d = elf_reader.dynamic(); d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_NEEDED) {
            action(fix_dt_needed(elf_reader.get_string(d->d_un.d_val), elf_reader.name()));
        }
    }
}

static bool load_library(android_namespace_t *ns,
                         LoadTask *task,
                         LoadTaskList *load_tasks,
                         int rtld_flags,
                         const std::string &realpath,
                         bool search_linked_namespaces) {
    off64_t file_offset = task->get_file_offset();
    const android_dlextinfo *extinfo = task->get_extinfo();

    const char *name = task->get_name();
    LOGI(
            "load_library(ns=%s, task=%s, flags=0x%x, realpath=%s, search_linked_namespaces=%d)",
            ns->get_name(), name, rtld_flags, realpath.c_str(), search_linked_namespaces);
    if ((file_offset % PAGE_SIZE) != 0) {
        LOGE("file offset for the library \"%s\" is not page-aligned: %" PRId64, name, file_offset);
        return false;
    }
    if (file_offset < 0) {
        LOGE("file offset for the library \"%s\" is negative: %" PRId64, name, file_offset);
        return false;
    }
    struct stat file_stat;
    if (TEMP_FAILURE_RETRY(fstat(task->get_fd(), &file_stat)) != 0) {
        LOGE("unable to stat file for the library \"%s\": %s", name, strerror(errno));
        return false;
    }
    if (file_offset >= file_stat.st_size) {
        LOGE("file offset for the library \"%s\" is past the end of the file: %" PRId64 " >= %" PRId64,
             name, file_offset, static_cast<int64_t>(file_stat.st_size));
        return false;
    }
    // we dont need accessible file so ignore this code
    //  if ((fs_stat.f_type != TMPFS_MAGIC) && (!ns->is_accessible(realpath))) {
    soinfo *si = soinfo_alloc(ns, realpath.c_str(), &file_stat, file_offset, rtld_flags);
    task->set_soinfo(si);
    // Read the ELF header and some of the segments.
    if (!task->read(realpath.c_str(), file_stat.st_size)) {
        task->remove_cached_elf_reader();
        task->set_soinfo(nullptr);
        soinfo_free(si);
        return false;
    }
    //这段代码位于Android动态链接器的上下文中，其主要目的是在加载共享库（.so文件）时，
    // 从ELF文件的动态节（.dynamic section）中读取特定的动态链接信息，并且暂时设置这些信息到正在加载的共享库对象（soinfo）中。
    // 具体来说，它关注于读取和设置三个关键的动态标签（dynamic tags）：DT_RUNPATH、DT_SONAME和DT_FLAGS_1
    const ElfReader &elf_reader = task->get_elf_reader();
    for (const ElfW(Dyn) *d = elf_reader.dynamic(); d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_RUNPATH) {
            const char *string = elf_reader.get_string(d->d_un.d_val);
            LOGI("elf_reader.dynamic() DT_RUNPATH %s",
                 string);
            si->set_dt_runpath(string);
        }
        if (d->d_tag == DT_SONAME) {

            const char *string = elf_reader.get_string(d->d_un.d_val);
            si->set_soname(string);
            LOGI("elf_reader.dynamic() DT_SONAME %s",
                 string);
        }
        // We need to identify a DF_1_GLOBAL library early so we can link it to namespaces.
        if (d->d_tag == DT_FLAGS_1) {
            si->set_dt_flags_1(d->d_un.d_val);
        }
    }
    for_each_dt_needed(task->get_elf_reader(), [&](const char *name) {
        LOGI("load_library(ns=%s, task=%s): Adding DT_NEEDED task: %s",
             ns->get_name(), task->get_name(), name);
        // our so  need load so
        //we use dlopen
        void *pVoid = dlopen(name, RTLD_NOW);
        LOGI("dlopen by dt needed %s  %p ", name, pVoid);
    });

    return true;
}

static bool load_library(android_namespace_t *ns,
                         LoadTask *task,
                         ZipArchiveCache *zip_archive_cache,
                         LoadTaskList *load_tasks,
                         int rtld_flags,
                         bool search_linked_namespaces) {
    const char *name = task->get_name();
    soinfo *needed_by = task->get_needed_by();
    //use dlopen extinfo is null; so  we dont need extinfo code
    LOGI(
            "load_library(ns=%s, task=%s, flags=0x%x, search_linked_namespaces=%d): calling "
            "open_library",
            ns->get_name(), name, rtld_flags, search_linked_namespaces);
    // Open the file.
    off64_t file_offset;
    std::string realpath;
    int fd = open_library(ns, zip_archive_cache, name, needed_by, &file_offset, &realpath);
    if (fd == -1) {
        LOGE("library \"%s\" not found", name);
        return false;
    }
    task->set_fd(fd, true);
    task->set_file_offset(file_offset);
    return load_library(ns, task, load_tasks, rtld_flags, realpath, search_linked_namespaces);
}

// Returns true if library was found and false otherwise
static bool find_loaded_library_by_soname(android_namespace_t *ns,
                                          const char *name,
                                          bool search_linked_namespaces,
                                          soinfo **candidate) {
    *candidate = nullptr;
    LOGI("find_loaded_library_by_soname %s ", name);
    // Ignore filename with path.
    if (strchr(name, '/') != nullptr) { //if we use dlopen this return false;
        return false;
    }
    return false;
}

static bool find_library_internal(android_namespace_t *ns,
                                  LoadTask *task,
                                  ZipArchiveCache *zip_archive_cache,
                                  LoadTaskList *load_tasks,
                                  int rtld_flags) {
    soinfo *candidate;
    if (find_loaded_library_by_soname(ns, task->get_name(), true /* search_linked_namespaces */,
                                      &candidate)) {
        LOGI(
                "find_library_internal(ns=%s, task=%s): Already loaded (by soname): %s",
                ns->get_name(), task->get_name(), candidate->get_realpath());
        task->set_soinfo(candidate);
        return true;
    }
    //start  load_library
    if (load_library(ns, task, zip_archive_cache, load_tasks, rtld_flags,
                     true /* search_linked_namespaces */)) {
        return true;
    }
    return false;
}
enum walk_action_result_t : uint32_t {
    kWalkStop = 0,
    kWalkContinue = 1,
    kWalkSkip = 2
};
template<typename F>
static bool walk_dependencies_tree(soinfo* root_soinfo, F action) {
    SoinfoLinkedList visit_list;
    SoinfoLinkedList visited;

    visit_list.push_back(root_soinfo);

    soinfo* si;
    while ((si = visit_list.pop_front()) != nullptr) {
        if (visited.contains(si)) {
            continue;
        }

        walk_action_result_t result = action(si);

        if (result == kWalkStop) {
            return false;
        }

        visited.push_back(si);

        if (result != kWalkSkip) {
            si->get_children().for_each([&](soinfo* child) {
                visit_list.push_back(child);
            });
        }
    }

    return true;
}
bool find_libraries(android_namespace_t *ns,
                    soinfo *start_with,
                    const char *const library_names[],
                    size_t library_names_count,
                    soinfo *soinfos[],
                    std::vector<soinfo *> *ld_preloads,
                    size_t ld_preloads_count,
                    int rtld_flags,
                    const android_dlextinfo *extinfo,
                    bool add_as_children,
                    std::vector<android_namespace_t *> *namespaces = nullptr) {
    // Step 0: prepare.
    // 第一步开始准备 加入一个tasks list 里
    std::unordered_map<const soinfo *, ElfReader> readers_map;
    LoadTaskList load_tasks;
    for (size_t i = 0; i < library_names_count; ++i) {
        const char *name = library_names[i];
        LOGI("load task create %s ", name);
        load_tasks.push_back(LoadTask::create(name, start_with, ns, &readers_map));
    }

    bool reserved_address_recursive = false;

    // If soinfos array is null allocate one on stack.
    // The array is needed in case of failure; for example
    // when library_names[] = {libone.so, libtwo.so} and libone.so
    // is loaded correctly but libtwo.so failed for some reason.
    // In this case libone.so should be unloaded on return.
    // See also implementation of failure_guard below.
    if (soinfos == nullptr) {
        size_t soinfos_size = sizeof(soinfo *) * library_names_count;
        soinfos = reinterpret_cast<soinfo **>(alloca(soinfos_size));
        memset(soinfos, 0, soinfos_size);
    }
    // list of libraries to link - see step 2.
    size_t soinfos_count = 0;

    ZipArchiveCache zip_archive_cache;

    // Step 1:
    //这一步是动态链接过程中的一个重要环节，其目的是扩展要加载的库（load_tasks）列表，
    // 以包括所有通过DT_NEEDED条目指定的依赖库。DT_NEEDED条目是在ELF（Executable and Linkable Format）文件的动态段中指定的，
    // 表示当前库需要加载的其他库。这一步骤并不立即加载这些依赖库，而是准备加载任务
    for (size_t i = 0; i < load_tasks.size(); ++i) {
        LoadTask *task = load_tasks[i];
        soinfo *needed_by = task->get_needed_by();
        bool is_dt_needed = needed_by != nullptr && (needed_by != start_with || add_as_children);
        task->set_extinfo(is_dt_needed ? nullptr : extinfo);
        task->set_dt_needed(is_dt_needed);

        LOGI("find_libraries(ns=%s): task=%s, is_dt_needed=%d", "null",
             task->get_name(), is_dt_needed);
        //
        // Note: start from the namespace that is stored in the LoadTask. This namespace
        // is different from the current namespace when the LoadTask is for a transitive
        // dependency and the lib that created the LoadTask is not found in the
        // current namespace but in one of the linked namespace.
        if (!find_library_internal(const_cast<android_namespace_t *>(task->get_start_from()),
                                   task,
                                   &zip_archive_cache,
                                   &load_tasks,
                                   rtld_flags)) {
            return false;
        }

        soinfo *si = task->get_soinfo();
        LOGI(" after find_library_internal call is_dt_needed %s %i", task->get_name(),
             is_dt_needed);
        if (is_dt_needed) {
            needed_by->add_child(si);
        }
//        // When ld_preloads is not null, the first
//        // ld_preloads_count libs are in fact ld_preloads.
        bool is_ld_preload = false;
        if (ld_preloads != nullptr && soinfos_count < ld_preloads_count) {
            ld_preloads->push_back(si);
            is_ld_preload = true;
        }
        if (soinfos_count < library_names_count) {
            LOGI("===call? ");
            soinfos[soinfos_count++] = si;
        }
//
//        // we dont need this code
////        if (is_ld_preload || (si->get_dt_flags_1() & DF_1_GLOBAL) != 0) {
//
////        }
//
//        // Step 2: Load libraries in random order (see b/24047022)
        LoadTaskList load_list;
        for (auto &&task: load_tasks) {
            soinfo *si = task->get_soinfo();
            auto pred = [&](const LoadTask *t) {
                return t->get_soinfo() == si;
            };
            if (!si->is_linked() &&
                std::find_if(load_list.begin(), load_list.end(), pred) == load_list.end()) {
                load_list.push_back(task);
            }
        }

//        // this is simple code because we dont need java load so,  extinfo always null
        address_space_params default_params;
        size_t relro_fd_offset = 0;
        for (auto &&task: load_list) {
            address_space_params *address_space = &default_params;
            if (!task->load(address_space)) {
                return false;
            }
        }
        // Step 3: pre-link all DT_NEEDED libraries in breadth first order.
        for (auto &&task: load_tasks) {
            soinfo *si = task->get_soinfo();
            LOGI("is linked %s %d ", si->get_realpath(), si->is_linked());
            if (!si->is_linked() && !si->prelink_image()) {
                return false;
            }
//            LOGI("register_soinfo_tls");
//            register_soinfo_tls(si);
        }
        // Step 4: Construct the global group. DF_1_GLOBAL bit is force set for LD_PRELOADed libs because
        // they must be added to the global group. Note: The DF_1_GLOBAL bit for a library is normally set
        // in step 3.
        LOGI("ld_preloads %p ", ld_preloads);
        if (ld_preloads != nullptr) {
            for (auto&& si : *ld_preloads) {
                si->set_dt_flags_1(si->get_dt_flags_1() | DF_1_GLOBAL);
            }
        }

        // Step 5: Collect roots of local_groups.
        // Whenever needed_by->si link crosses a namespace boundary it forms its own local_group.
        // Here we collect new roots to link them separately later on. Note that we need to avoid
        // collecting duplicates. Also the order is important. They need to be linked in the same
        // BFS order we link individual libraries.
        std::vector<soinfo*> local_group_roots;
        LOGI("start_with %p  add_as_children %i soinfos[0] %p", start_with,add_as_children, soinfos[0]);
        if (start_with != nullptr && add_as_children) {
            local_group_roots.push_back(start_with);
        } else {
            local_group_roots.push_back(soinfos[0]);
        }
        for (auto&& task : load_tasks) {
            soinfo* si = task->get_soinfo();

            bool is_dt_needed = needed_by != nullptr && (needed_by != start_with || add_as_children);
            LOGI("si %s is_dt_needed %i", si->get_realpath(), is_dt_needed);
//            LOGI("si %s needed_by %s", si->get_realpath(), needed_by->get_realpath());
            android_namespace_t* needed_by_ns =
                    is_dt_needed ? needed_by->get_primary_namespace() : ns;
            if (!si->is_linked() && si->get_primary_namespace() != needed_by_ns) {
                auto it = std::find(local_group_roots.begin(), local_group_roots.end(), si);
                LOGD(
                       "Crossing namespace boundary (si=%s@%p, si_ns=%s@%p, needed_by=%s@%p, ns=%s@%p, needed_by_ns=%s@%p) adding to local_group_roots: %s",
                       si->get_realpath(),
                       si,
                       si->get_primary_namespace()->get_name(),
                       si->get_primary_namespace(),
                       needed_by == nullptr ? "(nullptr)" : needed_by->get_realpath(),
                       needed_by,
                       ns->get_name(),
                       ns,
                       needed_by_ns->get_name(),
                       needed_by_ns,
                       it == local_group_roots.end() ? "yes" : "no");

                if (it == local_group_roots.end()) {
                    local_group_roots.push_back(si);
                }
            }
        }
        // Step 6: Link all local groups
        for (auto root : local_group_roots) {
            soinfo_list_t local_group;
            android_namespace_t* local_group_ns = root->get_primary_namespace();
            LOGI(" // Step 6: Link all local groups namespace %s   ", local_group_ns->get_name());
            walk_dependencies_tree(root,
                                   [&] (soinfo* si) {
                                       LOGI("walk_dependencies_tree %s ", si->get_realpath());
                                       if (local_group_ns->is_accessible(si)) {
                                           local_group.push_back(si);
                                           return kWalkContinue;
                                       } else {
                                           return kWalkSkip;
                                       }
                                   });
            soinfo_list_t global_group = local_group_ns->get_global_group();
            SymbolLookupList lookup_list(global_group, local_group);
            soinfo* local_group_root = local_group.front();
            bool linked = local_group.visit([&](soinfo* si) {
                // Even though local group may contain accessible soinfos from other namespaces
                // we should avoid linking them (because if they are not linked -> they
                // are in the local_group_roots and will be linked later).
                if (!si->is_linked() && si->get_primary_namespace() == local_group_ns) {
                    const android_dlextinfo* link_extinfo = nullptr;
                    if (si == soinfos[0] || reserved_address_recursive) {
                        // Only forward extinfo for the first library unless the recursive
                        // flag is set.
                        link_extinfo = extinfo;
                    }
                    LOGI("has_DT_SYMBOLIC %i ", si->has_DT_SYMBOLIC);
                    lookup_list.set_dt_symbolic_lib(si->has_DT_SYMBOLIC ? si : nullptr);
                    if (!si->link_image(lookup_list, local_group_root, link_extinfo, &relro_fd_offset)) {
                        return false;
                    }
                }

                return true;
            });
            LOGI("linkerd %i ", linked);
            if (!linked) {
                return false;
            }
            // Step 7: Mark all load_tasks as linked and increment refcounts
            // for references between load_groups (at this point it does not matter if
            // referenced load_groups were loaded by previous dlopen or as part of this
            // one on step 6)
            // 我们只dlopen 一个so这里是无所谓的执行
            if (start_with != nullptr && add_as_children) {
                start_with->set_linked();
            }
            for (auto&& task : load_tasks) {
                soinfo* si = task->get_soinfo();
                si->set_linked();
            }
            for (auto&& task : load_tasks) {
                soinfo* si = task->get_soinfo();
                soinfo* needed_by = task->get_needed_by();
                if (needed_by != nullptr &&
                    needed_by != start_with &&
                    needed_by->get_local_group_root() != si->get_local_group_root()) {
                    si->increment_ref_count();
                }
                LOGI("fd %i ", task->get_fd());
                //close fd
                close(task->get_fd());
            }
        }
    }
    return true;
}

static soinfo *find_library(android_namespace_t *ns,
                            const char *name, int rtld_flags,
                            const android_dlextinfo *extinfo,
                            soinfo *needed_by) {
    soinfo *si = nullptr;
    if (name == nullptr) {
//        si = solist_get_somain();
    } else if (!find_libraries(ns,
                               needed_by,
                               &name,
                               1,
                               &si,
                               nullptr,
                               0,
                               rtld_flags,
                               extinfo,
                               false /* add_as_children */)) {
        if (si != nullptr) {
//            soinfo_unload(si);
        }
        return nullptr;
    }
//    if (si!= nullptr){
//        si->increment_ref_count();
//    }
    return si;
}


/**
 *
 * @param name
 * @param flags
 * @param extinfo
 * @param caller_addr
 * @return
 */
void *do_dlopen(const char *name, int flags,
                const android_dlextinfo *extinfo,
                const void *caller_addr) {
    soinfo *const caller = find_containing_library(caller_addr);
    android_namespace_t *ns = get_caller_namespace(caller);
    if (ns != nullptr) {
        LOGI("get caller name space %s ",
             ns->get_name()); // return clns-4  maybe classloader name space -4?
    }
    if ((flags &
         ~(RTLD_NOW | RTLD_LAZY | RTLD_LOCAL | RTLD_GLOBAL | RTLD_NODELETE | RTLD_NOLOAD)) != 0) {
        LOGE("invalid flags to dlopen: %x", flags);
        return nullptr;
    }
    const char *translated_name = name;
    soinfo *si = find_library(ns, translated_name, flags, extinfo, caller);
    LOGI("find_library %s %p", translated_name, si);
    if (si != nullptr) {
        void *handle = si->to_handle();
        LOGI("... dlopen calling constructors: realpath=\"%s\", soname=\"%s\", handle=%p",
                si->get_realpath(), si->get_soname(), handle);
        si->call_constructors();

        return handle;
    }
    return nullptr;
}

template <typename F>
static bool for_each_verdef(const soinfo* si, F functor) {
    if (!si->has_min_version(2)) {
        return true;
    }

    uintptr_t verdef_ptr = si->get_verdef_ptr();
    if (verdef_ptr == 0) {
        return true;
    }

    size_t offset = 0;

    size_t verdef_cnt = si->get_verdef_cnt();
    for (size_t i = 0; i<verdef_cnt; ++i) {
        const ElfW(Verdef)* verdef = reinterpret_cast<ElfW(Verdef)*>(verdef_ptr + offset);
        size_t verdaux_offset = offset + verdef->vd_aux;
        offset += verdef->vd_next;

        if (verdef->vd_version != 1) {
            LOGE("unsupported verdef[%zd] vd_version: %d (expected 1) library: %s",
                   i, verdef->vd_version, si->get_realpath());
            return false;
        }

        if ((verdef->vd_flags & VER_FLG_BASE) != 0) {
            // "this is the version of the file itself.  It must not be used for
            //  matching a symbol. It can be used to match references."
            //
            // http://www.akkadia.org/drepper/symbol-versioning
            continue;
        }

        if (verdef->vd_cnt == 0) {
            LOGE("invalid verdef[%zd] vd_cnt == 0 (version without a name)", i);
            return false;
        }

        const ElfW(Verdaux)* verdaux = reinterpret_cast<ElfW(Verdaux)*>(verdef_ptr + verdaux_offset);

        if (functor(i, verdef, verdaux) == true) {
            break;
        }
    }

    return true;
}
// Validate the library's verdef section. On error, returns false and invokes DL_ERR.
bool validate_verdef_section(const soinfo* si) {
    return for_each_verdef(si,
                           [&](size_t, const ElfW(Verdef)*, const ElfW(Verdaux)*) {
                               return false;
                           });
}

ElfW(Versym) find_verdef_version_index(const soinfo* si, const version_info* vi) {
    if (vi == nullptr) {
        return 0;
    }
    ElfW(Versym) result = 1;
    if (!for_each_verdef(si,
                         [&](size_t, const ElfW(Verdef)* verdef, const ElfW(Verdaux)* verdaux) {
                             if (verdef->vd_hash == vi->elf_hash &&
                                 strcmp(vi->name, si->get_string(verdaux->vda_name)) == 0) {
                                 result = verdef->vd_ndx;
                                 return true;
                             }

                             return false;
                         }
    )) {
        // verdef should have already been validated in prelink_image.

    }
    return result;
}
/**
 * 最关键的一步 重定位和链接
 * @return
 */
bool soinfo::prelink_image() {
    if (flags_ & FLAG_PRELINKED) return true;
    /* Extract dynamic section */
    ElfW(Word) dynamic_flags = 0;
    phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);
    /* We can't log anything until the linker is relocated */
    bool relocating_linker = (flags_ & FLAG_LINKER) != 0;
    if (!relocating_linker) {
        LOGI("[ Linking \"%s\" ]", get_realpath());
        LOGI("si->base = %p si->flags = 0x%08x load_bai %llx", reinterpret_cast<void *>(base), flags_,
             load_bias);
    }
    if (dynamic == nullptr) {
        if (!relocating_linker) {
            LOGE("missing PT_DYNAMIC in \"%s\"", get_realpath());
        }
        return false;
    } else {
        if (!relocating_linker) {
            LOGI("dynamic = %p", dynamic);
        }
    }
#if defined(__arm__)
    LOGE("sorry we do not support arm");
#endif
    TlsSegment tls_segment;
    if (__bionic_get_tls_segment(phdr, phnum, load_bias, &tls_segment)) {
        if (!__bionic_check_tls_alignment(&tls_segment.alignment)) {
            if (!relocating_linker) {
                LOGE("TLS segment alignment in \"%s\" is not a power of 2: %zu",
                     get_realpath(), tls_segment.alignment);
            }
            return false;
        }
        tls_ = std::make_unique<soinfo_tls>();
        tls_->segment = tls_segment;
        LOGI("set tls segment %p %zu %zu %p %zu", tls_segment.size, tls_segment.alignment,
             tls_segment.init_ptr, tls_segment.init_size);
    }
    uint32_t needed_count = 0;
    for (ElfW(Dyn) *d = dynamic; d->d_tag != DT_NULL; ++d) {
//        LOGD("d = %p, d[0](tag) = %p d[1](val) = %p",
//             d, reinterpret_cast<void *>(d->d_tag), reinterpret_cast<void *>(d->d_un.d_val));
        switch (d->d_tag) {
            case DT_SONAME:
                // this is parsed after we have strtab initialized (see below).
                break;
            case DT_HASH:
                nbucket_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[0];
                nchain_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[1];
                bucket_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr + 8);
                chain_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr + 8 + nbucket_ * 4);
                break;
            case DT_GNU_HASH:
                gnu_nbucket_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[0];
                // skip symndx
                gnu_maskwords_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[2];
                gnu_shift2_ = reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[3];

                gnu_bloom_filter_ = reinterpret_cast<ElfW(Addr) *>(load_bias + d->d_un.d_ptr + 16);
                gnu_bucket_ = reinterpret_cast<uint32_t *>(gnu_bloom_filter_ + gnu_maskwords_);
                // amend chain for symndx = header[1]
                gnu_chain_ = gnu_bucket_ + gnu_nbucket_ -
                             reinterpret_cast<uint32_t *>(load_bias + d->d_un.d_ptr)[1];

                if (!powerof2(gnu_maskwords_)) {
                    LOGE("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
                         gnu_maskwords_, get_realpath());
                    return false;
                }
                --gnu_maskwords_;

                flags_ |= FLAG_GNU_HASH;
                break;
            case DT_STRTAB:
                strtab_ = reinterpret_cast<const char *>(load_bias + d->d_un.d_ptr);
                break;
            case DT_STRSZ:
                strtab_size_ = d->d_un.d_val;
                break;
            case DT_SYMTAB:
                symtab_ = reinterpret_cast<ElfW(Sym) *>(load_bias + d->d_un.d_ptr);
                break;
            case DT_SYMENT:
                if (d->d_un.d_val != sizeof(ElfW(Sym))) {
                    LOGE("invalid DT_SYMENT: %zd in \"%s\"",
                         static_cast<size_t>(d->d_un.d_val), get_realpath());
                    return false;
                }
                break;
            case DT_PLTREL:
#if defined(USE_RELA)
                if (d->d_un.d_val != DT_RELA) {
                    LOGE("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", get_realpath());
                    return false;
                }
#else
                if (d->d_un.d_val != DT_REL) {
          DL_ERR("unsupported DT_PLTREL in \"%s\"; expected DT_REL", get_realpath());
          return false;
        }
#endif
                break;
            case DT_JMPREL:
#if defined(USE_RELA)
                plt_rela_ = reinterpret_cast<ElfW(Rela) *>(load_bias + d->d_un.d_ptr);
#else
                plt_rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
#endif
                break;
            case DT_PLTRELSZ:
#if defined(USE_RELA)
                plt_rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
#else
                plt_rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
#endif
                break;
            case DT_PLTGOT:
                // Ignored (because RTLD_LAZY is not supported).
                break;
            case DT_DEBUG:
                // Ignored (because DT_DEBUG is not supported).
                break;
#if defined(USE_RELA)
            case DT_RELA:
                rela_ = reinterpret_cast<ElfW(Rela) *>(load_bias + d->d_un.d_ptr);
                break;

            case DT_RELASZ:
                rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
                break;

            case DT_ANDROID_RELA:
                android_relocs_ = reinterpret_cast<uint8_t *>(load_bias + d->d_un.d_ptr);
                break;

            case DT_ANDROID_RELASZ:
                android_relocs_size_ = d->d_un.d_val;
                break;

            case DT_ANDROID_REL:
                LOGE("unsupported DT_ANDROID_REL in \"%s\"", get_realpath());
                return false;

            case DT_ANDROID_RELSZ:
                LOGE("unsupported DT_ANDROID_RELSZ in \"%s\"", get_realpath());
                return false;

            case DT_RELAENT:
                if (d->d_un.d_val != sizeof(ElfW(Rela))) {
                    LOGE("invalid DT_RELAENT: %zd", static_cast<size_t>(d->d_un.d_val));
                    return false;
                }
                break;

                // Ignored (see DT_RELCOUNT comments for details).
            case DT_RELACOUNT:
                break;

            case DT_REL:
                LOGE("unsupported DT_REL in \"%s\"", get_realpath());
                return false;

            case DT_RELSZ:
                LOGE("unsupported DT_RELSZ in \"%s\"", get_realpath());
                return false;
#else
                case DT_REL:
                  rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
                  break;

                case DT_RELSZ:
                  rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
                  break;

                case DT_RELENT:
                  if (d->d_un.d_val != sizeof(ElfW(Rel))) {
                    DL_ERR("invalid DT_RELENT: %zd", static_cast<size_t>(d->d_un.d_val));
                    return false;
                  }
                  break;

                case DT_ANDROID_REL:
                  android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
                  break;

                case DT_ANDROID_RELSZ:
                  android_relocs_size_ = d->d_un.d_val;
                  break;

                case DT_ANDROID_RELA:
                  DL_ERR("unsupported DT_ANDROID_RELA in \"%s\"", get_realpath());
                  return false;

                case DT_ANDROID_RELASZ:
                  DL_ERR("unsupported DT_ANDROID_RELASZ in \"%s\"", get_realpath());
                  return false;

                // "Indicates that all RELATIVE relocations have been concatenated together,
                // and specifies the RELATIVE relocation count."
                //
                // TODO: Spec also mentions that this can be used to optimize relocation process;
                // Not currently used by bionic linker - ignored.
                case DT_RELCOUNT:
                  break;

                case DT_RELA:
                  DL_ERR("unsupported DT_RELA in \"%s\"", get_realpath());
                  return false;

                case DT_RELASZ:
                  DL_ERR("unsupported DT_RELASZ in \"%s\"", get_realpath());
                  return false;
#endif
            case DT_RELR:
            case DT_ANDROID_RELR:
                relr_ = reinterpret_cast<ElfW(Relr) *>(load_bias + d->d_un.d_ptr);
                break;

            case DT_RELRSZ:
            case DT_ANDROID_RELRSZ:
                relr_count_ = d->d_un.d_val / sizeof(ElfW(Relr));
                break;

            case DT_RELRENT:
            case DT_ANDROID_RELRENT:
                if (d->d_un.d_val != sizeof(ElfW(Relr))) {
                    LOGE("invalid DT_RELRENT: %zd", static_cast<size_t>(d->d_un.d_val));
                    return false;
                }
                break;

                // Ignored (see DT_RELCOUNT comments for details).
                // There is no DT_RELRCOUNT specifically because it would only be ignored.
            case DT_ANDROID_RELRCOUNT:
                break;
            case DT_INIT:
                init_func_ = reinterpret_cast<linker_ctor_function_t>(load_bias + d->d_un.d_ptr);
                LOGD("%s constructors (DT_INIT) found at %p", get_realpath(), init_func_);
                break;
            case DT_FINI:
                fini_func_ = reinterpret_cast<linker_dtor_function_t>(load_bias + d->d_un.d_ptr);
                LOGD("%s destructors (DT_FINI) found at %p", get_realpath(), fini_func_);
                break;
            case DT_INIT_ARRAY:
                init_array_ = reinterpret_cast<linker_ctor_function_t *>(load_bias + d->d_un.d_ptr);

                LOGD("%s constructors (DT_INIT_ARRAY) found at %p  load_bias%llx ptr %llx", get_realpath(), init_array_,
                     load_bias,d->d_un.d_ptr);
                break;

            case DT_INIT_ARRAYSZ:
                init_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
                LOGD("%s constructors (DT_INIT_ARRAYSZ) %u", get_realpath(), init_array_count_);
                break;
            case DT_FINI_ARRAY:
                fini_array_ = reinterpret_cast<linker_dtor_function_t *>(load_bias + d->d_un.d_ptr);
                LOGD("%s destructors (DT_FINI_ARRAY) found at %p", get_realpath(), fini_array_);
                break;
            case DT_FINI_ARRAYSZ:
                fini_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
                break;

            case DT_PREINIT_ARRAY:
                preinit_array_ = reinterpret_cast<linker_ctor_function_t *>(load_bias +
                                                                            d->d_un.d_ptr);
                LOGD("%s constructors (DT_PREINIT_ARRAY) found at %p", get_realpath(),
                     preinit_array_);
                break;

            case DT_PREINIT_ARRAYSZ:
                preinit_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
                break;
            case DT_TEXTREL:
#if defined(__LP64__)
                LOGE("\"%s\" has text relocations", get_realpath());
                return false;
#else
                has_text_relocations = true;
                break;
#endif
            case DT_SYMBOLIC:
                has_DT_SYMBOLIC = true;
                break;
            case DT_NEEDED:
                ++needed_count;
                break;
            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) {
#if defined(__LP64__)
                    LOGE("\"%s\" has text relocations", get_realpath());
                    return false;
#else
                    has_text_relocations = true;
#endif
                }
                if (d->d_un.d_val & DF_SYMBOLIC) {
                    has_DT_SYMBOLIC = true;
                }
                break;
            case DT_FLAGS_1:
                set_dt_flags_1(d->d_un.d_val);

                if ((d->d_un.d_val & ~SUPPORTED_DT_FLAGS_1) != 0) {
                    LOGW("Warning: \"%s\" has unsupported flags DT_FLAGS_1=%p "
                            "(ignoring unsupported flags)",
                            get_realpath(), reinterpret_cast<void*>(d->d_un.d_val));
                }
                break;
                // Ignored: "Its use has been superseded by the DF_BIND_NOW flag"
            case DT_BIND_NOW:
                break;
            case DT_VERSYM:
                versym_ = reinterpret_cast<ElfW(Versym)*>(load_bias + d->d_un.d_ptr);
                break;
            case DT_VERDEF:
                verdef_ptr_ = load_bias + d->d_un.d_ptr;
                break;
            case DT_VERDEFNUM:
                verdef_cnt_ = d->d_un.d_val;
                break;

            case DT_VERNEED:
                verneed_ptr_ = load_bias + d->d_un.d_ptr;
                break;

            case DT_VERNEEDNUM:
                verneed_cnt_ = d->d_un.d_val;
                break;

            case DT_RUNPATH:
                // this is parsed after we have strtab initialized (see below).
                break;

            case DT_TLSDESC_GOT:
            case DT_TLSDESC_PLT:
                // These DT entries are used for lazy TLSDESC relocations. Bionic
                // resolves everything eagerly, so these can be ignored.
                break;
#if defined(__aarch64__)
            case DT_AARCH64_BTI_PLT:
            case DT_AARCH64_PAC_PLT:
            case DT_AARCH64_VARIANT_PCS:
                // Ignored: AArch64 processor-specific dynamic array tags.
                break;
#endif
            default:
                if (!relocating_linker) {
                    const char* tag_name;
                    if (d->d_tag == DT_RPATH) {
                        tag_name = "DT_RPATH";
                    } else if (d->d_tag == DT_ENCODING) {
                        tag_name = "DT_ENCODING";
                    } else if (d->d_tag >= DT_LOOS && d->d_tag <= DT_HIOS) {
                        tag_name = "unknown OS-specific";
                    } else if (d->d_tag >= DT_LOPROC && d->d_tag <= DT_HIPROC) {
                        tag_name = "unknown processor-specific";
                    } else {
                        tag_name = "unknown";
                    }
                    LOGD("Warning: \"%s\" unused DT entry: %s (type %p arg %p) (ignoring)",
                            get_realpath(),
                            tag_name,
                            reinterpret_cast<void*>(d->d_tag),
                            reinterpret_cast<void*>(d->d_un.d_val));
                }
                break;
        }
    }
    LOGD("si->base = %p, si->strtab = %p, si->symtab = %p",
          reinterpret_cast<void*>(base), strtab_, symtab_);
    // Validity checks.
    if (relocating_linker && needed_count != 0) {
        LOGE("linker cannot have DT_NEEDED dependencies on other libraries");
        return false;
    }
    if (nbucket_ == 0 && gnu_nbucket_ == 0) {
        LOGE("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
               "(new hash type from the future?)", get_realpath());
        return false;
    }
    if (strtab_ == nullptr) {
        LOGE("empty/missing DT_STRTAB in \"%s\"", get_realpath());
        return false;
    }
    if (symtab_ == nullptr) {
        LOGE("empty/missing DT_SYMTAB in \"%s\"", get_realpath());
        return false;
    }
    // Second pass - parse entries relying on strtab. Skip this while relocating the linker so as to
    // avoid doing heap allocations until later in the linker's initialization.
    if (!relocating_linker) {
        for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
            switch (d->d_tag) {
                case DT_SONAME:
                    set_soname(get_string(d->d_un.d_val));
                    break;
                case DT_RUNPATH:
                    set_dt_runpath(get_string(d->d_un.d_val));
                    break;
            }
        }
    }
    // Validate each library's verdef section once, so we don't have to validate
    // it each time we look up a symbol with a version.
    if (!validate_verdef_section(this)) return false;
    flags_ |= FLAG_PRELINKED;
    LOGI("prelink_image success %s", get_realpath());
    return true;
}

bool VersionTracker::init_verneed(const soinfo* si_from) {
    uintptr_t verneed_ptr = si_from->get_verneed_ptr();

    if (verneed_ptr == 0) {
        return true;
    }

    size_t verneed_cnt = si_from->get_verneed_cnt();

    for (size_t i = 0, offset = 0; i<verneed_cnt; ++i) {
        const ElfW(Verneed)* verneed = reinterpret_cast<ElfW(Verneed)*>(verneed_ptr + offset);
        size_t vernaux_offset = offset + verneed->vn_aux;
        offset += verneed->vn_next;

        if (verneed->vn_version != 1) {
            LOGE("unsupported verneed[%zd] vn_version: %d (expected 1)", i, verneed->vn_version);
            return false;
        }

        const char* target_soname = si_from->get_string(verneed->vn_file);
        // find it in dependencies
        LOGI("target_soname %s", target_soname);
        soinfo* target_si = si_from->get_children().find_if(
                [&](const soinfo* si) { return strcmp(si->get_soname(), target_soname) == 0; });
        if (target_si== nullptr){
            auto solist = linker_get_solist();
            for (auto info : solist) {
                //cast to soinfo
                soinfo* so = reinterpret_cast<soinfo*>(info);
                //match this so
                if (strcmp(so->get_soname(), target_soname) == 0){
                    target_si = so;
                    LOGI("find so in solist %s ",target_soname);
                    break;
                }
            }
        }
        if (target_si == nullptr) {
            //get is from solist
            LOGE("cannot find \"%s\" from verneed[%zd] in DT_NEEDED list for \"%s\"",
                   target_soname, i, si_from->get_realpath());
            return false;
        }

        for (size_t j = 0; j<verneed->vn_cnt; ++j) {
            const ElfW(Vernaux)* vernaux = reinterpret_cast<ElfW(Vernaux)*>(verneed_ptr + vernaux_offset);
            vernaux_offset += vernaux->vna_next;

            const ElfW(Word) elf_hash = vernaux->vna_hash;
            const char* ver_name = si_from->get_string(vernaux->vna_name);
            ElfW(Half) source_index = vernaux->vna_other;

            add_version_info(source_index, elf_hash, ver_name, target_si);
        }
    }

    return true;
}
bool VersionTracker::init(const soinfo *si_from) {
    if (!si_from->has_min_version(2)) {
        return true;
    }
    //这段代码是 Android 动态链接器（linker）的一部分，具体负责初始化动态链接库（soinfo 对象）的版本需求信息（version requirement）。
    // 它从一个给定的 soinfo 实例（代表一个已加载的共享库）读取版本需求信息，并将这些信息与该库的依赖项进行匹配。这是动态链接过程中处理符号版本控制的一环。
    return init_verneed(si_from)&& init_verdef(si_from);
}

void
VersionTracker::add_version_info(size_t source_index, Elf64_Word elf_hash, const char *ver_name,
                                 const soinfo *target_si) {
    if (source_index >= version_infos.size()) {
        version_infos.resize(source_index+1);
    }
    version_infos[source_index].elf_hash = elf_hash;
    version_infos[source_index].name = ver_name;
    version_infos[source_index].target_si = target_si;
    LOGI("add version info %s %s %p", ver_name, target_si->get_realpath(), target_si);
}

bool VersionTracker::init_verdef(const soinfo *si_from) {
    return for_each_verdef(si_from,
                           [&](size_t, const ElfW(Verdef)* verdef, const ElfW(Verdaux)* verdaux) {
                               add_version_info(verdef->vd_ndx, verdef->vd_hash,
                                                si_from->get_string(verdaux->vda_name), si_from);
                               return false;
                           }
    );
}

const version_info *VersionTracker::get_version_info(Elf64_Versym source_symver) const {
    if (source_symver < 2 ||
        source_symver >= version_infos.size() ||
        version_infos[source_symver].name == nullptr) {
        return nullptr;
    }
    return &version_infos[source_symver];
}

ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr) {
     return 0;


}
