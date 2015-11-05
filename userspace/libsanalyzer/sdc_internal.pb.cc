// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: sdc_internal.proto

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "sdc_internal.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace sdc_internal {

namespace {

const ::google::protobuf::Descriptor* container_mounts_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  container_mounts_reflection_ = NULL;
const ::google::protobuf::Descriptor* mounted_fs_response_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  mounted_fs_response_reflection_ = NULL;
const ::google::protobuf::Descriptor* container_info_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  container_info_reflection_ = NULL;
const ::google::protobuf::Descriptor* mounted_fs_request_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  mounted_fs_request_reflection_ = NULL;

}  // namespace


void protobuf_AssignDesc_sdc_5finternal_2eproto() {
  protobuf_AddDesc_sdc_5finternal_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "sdc_internal.proto");
  GOOGLE_CHECK(file != NULL);
  container_mounts_descriptor_ = file->message_type(0);
  static const int container_mounts_offsets_[2] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(container_mounts, container_id_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(container_mounts, mounts_),
  };
  container_mounts_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      container_mounts_descriptor_,
      container_mounts::default_instance_,
      container_mounts_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(container_mounts, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(container_mounts, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(container_mounts));
  mounted_fs_response_descriptor_ = file->message_type(1);
  static const int mounted_fs_response_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(mounted_fs_response, containers_),
  };
  mounted_fs_response_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      mounted_fs_response_descriptor_,
      mounted_fs_response::default_instance_,
      mounted_fs_response_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(mounted_fs_response, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(mounted_fs_response, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(mounted_fs_response));
  container_info_descriptor_ = file->message_type(2);
  static const int container_info_offsets_[3] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(container_info, id_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(container_info, pid_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(container_info, vpid_),
  };
  container_info_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      container_info_descriptor_,
      container_info::default_instance_,
      container_info_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(container_info, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(container_info, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(container_info));
  mounted_fs_request_descriptor_ = file->message_type(3);
  static const int mounted_fs_request_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(mounted_fs_request, containers_),
  };
  mounted_fs_request_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      mounted_fs_request_descriptor_,
      mounted_fs_request::default_instance_,
      mounted_fs_request_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(mounted_fs_request, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(mounted_fs_request, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(mounted_fs_request));
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_sdc_5finternal_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    container_mounts_descriptor_, &container_mounts::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    mounted_fs_response_descriptor_, &mounted_fs_response::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    container_info_descriptor_, &container_info::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    mounted_fs_request_descriptor_, &mounted_fs_request::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_sdc_5finternal_2eproto() {
  delete container_mounts::default_instance_;
  delete container_mounts_reflection_;
  delete mounted_fs_response::default_instance_;
  delete mounted_fs_response_reflection_;
  delete container_info::default_instance_;
  delete container_info_reflection_;
  delete mounted_fs_request::default_instance_;
  delete mounted_fs_request_reflection_;
}

void protobuf_AddDesc_sdc_5finternal_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::draiosproto::protobuf_AddDesc_draios_2eproto();
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\022sdc_internal.proto\022\014sdc_internal\032\014drai"
    "os.proto\"Q\n\020container_mounts\022\024\n\014containe"
    "r_id\030\001 \002(\t\022\'\n\006mounts\030\002 \003(\0132\027.draiosproto"
    ".mounted_fs\"I\n\023mounted_fs_response\0222\n\nco"
    "ntainers\030\001 \003(\0132\036.sdc_internal.container_"
    "mounts\"7\n\016container_info\022\n\n\002id\030\001 \002(\t\022\013\n\003"
    "pid\030\002 \002(\004\022\014\n\004vpid\030\003 \002(\004\"F\n\022mounted_fs_re"
    "quest\0220\n\ncontainers\030\001 \003(\0132\034.sdc_internal"
    ".container_infoB\002H\001X\000", 341);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "sdc_internal.proto", &protobuf_RegisterTypes);
  container_mounts::default_instance_ = new container_mounts();
  mounted_fs_response::default_instance_ = new mounted_fs_response();
  container_info::default_instance_ = new container_info();
  mounted_fs_request::default_instance_ = new mounted_fs_request();
  container_mounts::default_instance_->InitAsDefaultInstance();
  mounted_fs_response::default_instance_->InitAsDefaultInstance();
  container_info::default_instance_->InitAsDefaultInstance();
  mounted_fs_request::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_sdc_5finternal_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_sdc_5finternal_2eproto {
  StaticDescriptorInitializer_sdc_5finternal_2eproto() {
    protobuf_AddDesc_sdc_5finternal_2eproto();
  }
} static_descriptor_initializer_sdc_5finternal_2eproto_;

// ===================================================================

#ifndef _MSC_VER
const int container_mounts::kContainerIdFieldNumber;
const int container_mounts::kMountsFieldNumber;
#endif  // !_MSC_VER

container_mounts::container_mounts()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void container_mounts::InitAsDefaultInstance() {
}

container_mounts::container_mounts(const container_mounts& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void container_mounts::SharedCtor() {
  _cached_size_ = 0;
  container_id_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

container_mounts::~container_mounts() {
  SharedDtor();
}

void container_mounts::SharedDtor() {
  if (container_id_ != &::google::protobuf::internal::kEmptyString) {
    delete container_id_;
  }
  if (this != default_instance_) {
  }
}

void container_mounts::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* container_mounts::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return container_mounts_descriptor_;
}

const container_mounts& container_mounts::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_sdc_5finternal_2eproto();
  return *default_instance_;
}

container_mounts* container_mounts::default_instance_ = NULL;

container_mounts* container_mounts::New() const {
  return new container_mounts;
}

void container_mounts::Clear() {
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (has_container_id()) {
      if (container_id_ != &::google::protobuf::internal::kEmptyString) {
        container_id_->clear();
      }
    }
  }
  mounts_.Clear();
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool container_mounts::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required string container_id = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_container_id()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8String(
            this->container_id().data(), this->container_id().length(),
            ::google::protobuf::internal::WireFormat::PARSE);
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(18)) goto parse_mounts;
        break;
      }

      // repeated .draiosproto.mounted_fs mounts = 2;
      case 2: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
         parse_mounts:
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessageNoVirtual(
                input, add_mounts()));
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(18)) goto parse_mounts;
        if (input->ExpectAtEnd()) return true;
        break;
      }

      default: {
      handle_uninterpreted:
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          return true;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
  return true;
#undef DO_
}

void container_mounts::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // required string container_id = 1;
  if (has_container_id()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->container_id().data(), this->container_id().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    ::google::protobuf::internal::WireFormatLite::WriteString(
      1, this->container_id(), output);
  }

  // repeated .draiosproto.mounted_fs mounts = 2;
  for (int i = 0; i < this->mounts_size(); i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      2, this->mounts(i), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* container_mounts::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // required string container_id = 1;
  if (has_container_id()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->container_id().data(), this->container_id().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        1, this->container_id(), target);
  }

  // repeated .draiosproto.mounted_fs mounts = 2;
  for (int i = 0; i < this->mounts_size(); i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      WriteMessageNoVirtualToArray(
        2, this->mounts(i), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int container_mounts::ByteSize() const {
  int total_size = 0;

  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required string container_id = 1;
    if (has_container_id()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->container_id());
    }

  }
  // repeated .draiosproto.mounted_fs mounts = 2;
  total_size += 1 * this->mounts_size();
  for (int i = 0; i < this->mounts_size(); i++) {
    total_size +=
      ::google::protobuf::internal::WireFormatLite::MessageSizeNoVirtual(
        this->mounts(i));
  }

  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void container_mounts::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const container_mounts* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const container_mounts*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void container_mounts::MergeFrom(const container_mounts& from) {
  GOOGLE_CHECK_NE(&from, this);
  mounts_.MergeFrom(from.mounts_);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_container_id()) {
      set_container_id(from.container_id());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void container_mounts::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void container_mounts::CopyFrom(const container_mounts& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool container_mounts::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000001) != 0x00000001) return false;

  for (int i = 0; i < mounts_size(); i++) {
    if (!this->mounts(i).IsInitialized()) return false;
  }
  return true;
}

void container_mounts::Swap(container_mounts* other) {
  if (other != this) {
    std::swap(container_id_, other->container_id_);
    mounts_.Swap(&other->mounts_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata container_mounts::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = container_mounts_descriptor_;
  metadata.reflection = container_mounts_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int mounted_fs_response::kContainersFieldNumber;
#endif  // !_MSC_VER

mounted_fs_response::mounted_fs_response()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void mounted_fs_response::InitAsDefaultInstance() {
}

mounted_fs_response::mounted_fs_response(const mounted_fs_response& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void mounted_fs_response::SharedCtor() {
  _cached_size_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

mounted_fs_response::~mounted_fs_response() {
  SharedDtor();
}

void mounted_fs_response::SharedDtor() {
  if (this != default_instance_) {
  }
}

void mounted_fs_response::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* mounted_fs_response::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return mounted_fs_response_descriptor_;
}

const mounted_fs_response& mounted_fs_response::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_sdc_5finternal_2eproto();
  return *default_instance_;
}

mounted_fs_response* mounted_fs_response::default_instance_ = NULL;

mounted_fs_response* mounted_fs_response::New() const {
  return new mounted_fs_response;
}

void mounted_fs_response::Clear() {
  containers_.Clear();
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool mounted_fs_response::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // repeated .sdc_internal.container_mounts containers = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
         parse_containers:
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessageNoVirtual(
                input, add_containers()));
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(10)) goto parse_containers;
        if (input->ExpectAtEnd()) return true;
        break;
      }

      default: {
      handle_uninterpreted:
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          return true;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
  return true;
#undef DO_
}

void mounted_fs_response::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // repeated .sdc_internal.container_mounts containers = 1;
  for (int i = 0; i < this->containers_size(); i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      1, this->containers(i), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* mounted_fs_response::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // repeated .sdc_internal.container_mounts containers = 1;
  for (int i = 0; i < this->containers_size(); i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      WriteMessageNoVirtualToArray(
        1, this->containers(i), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int mounted_fs_response::ByteSize() const {
  int total_size = 0;

  // repeated .sdc_internal.container_mounts containers = 1;
  total_size += 1 * this->containers_size();
  for (int i = 0; i < this->containers_size(); i++) {
    total_size +=
      ::google::protobuf::internal::WireFormatLite::MessageSizeNoVirtual(
        this->containers(i));
  }

  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void mounted_fs_response::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const mounted_fs_response* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const mounted_fs_response*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void mounted_fs_response::MergeFrom(const mounted_fs_response& from) {
  GOOGLE_CHECK_NE(&from, this);
  containers_.MergeFrom(from.containers_);
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void mounted_fs_response::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void mounted_fs_response::CopyFrom(const mounted_fs_response& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool mounted_fs_response::IsInitialized() const {

  for (int i = 0; i < containers_size(); i++) {
    if (!this->containers(i).IsInitialized()) return false;
  }
  return true;
}

void mounted_fs_response::Swap(mounted_fs_response* other) {
  if (other != this) {
    containers_.Swap(&other->containers_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata mounted_fs_response::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = mounted_fs_response_descriptor_;
  metadata.reflection = mounted_fs_response_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int container_info::kIdFieldNumber;
const int container_info::kPidFieldNumber;
const int container_info::kVpidFieldNumber;
#endif  // !_MSC_VER

container_info::container_info()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void container_info::InitAsDefaultInstance() {
}

container_info::container_info(const container_info& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void container_info::SharedCtor() {
  _cached_size_ = 0;
  id_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  pid_ = GOOGLE_ULONGLONG(0);
  vpid_ = GOOGLE_ULONGLONG(0);
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

container_info::~container_info() {
  SharedDtor();
}

void container_info::SharedDtor() {
  if (id_ != &::google::protobuf::internal::kEmptyString) {
    delete id_;
  }
  if (this != default_instance_) {
  }
}

void container_info::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* container_info::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return container_info_descriptor_;
}

const container_info& container_info::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_sdc_5finternal_2eproto();
  return *default_instance_;
}

container_info* container_info::default_instance_ = NULL;

container_info* container_info::New() const {
  return new container_info;
}

void container_info::Clear() {
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (has_id()) {
      if (id_ != &::google::protobuf::internal::kEmptyString) {
        id_->clear();
      }
    }
    pid_ = GOOGLE_ULONGLONG(0);
    vpid_ = GOOGLE_ULONGLONG(0);
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool container_info::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required string id = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_id()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8String(
            this->id().data(), this->id().length(),
            ::google::protobuf::internal::WireFormat::PARSE);
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(16)) goto parse_pid;
        break;
      }

      // required uint64 pid = 2;
      case 2: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_pid:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint64, ::google::protobuf::internal::WireFormatLite::TYPE_UINT64>(
                 input, &pid_)));
          set_has_pid();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(24)) goto parse_vpid;
        break;
      }

      // required uint64 vpid = 3;
      case 3: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_vpid:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint64, ::google::protobuf::internal::WireFormatLite::TYPE_UINT64>(
                 input, &vpid_)));
          set_has_vpid();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectAtEnd()) return true;
        break;
      }

      default: {
      handle_uninterpreted:
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          return true;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
  return true;
#undef DO_
}

void container_info::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // required string id = 1;
  if (has_id()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->id().data(), this->id().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    ::google::protobuf::internal::WireFormatLite::WriteString(
      1, this->id(), output);
  }

  // required uint64 pid = 2;
  if (has_pid()) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt64(2, this->pid(), output);
  }

  // required uint64 vpid = 3;
  if (has_vpid()) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt64(3, this->vpid(), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* container_info::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // required string id = 1;
  if (has_id()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->id().data(), this->id().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        1, this->id(), target);
  }

  // required uint64 pid = 2;
  if (has_pid()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteUInt64ToArray(2, this->pid(), target);
  }

  // required uint64 vpid = 3;
  if (has_vpid()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteUInt64ToArray(3, this->vpid(), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int container_info::ByteSize() const {
  int total_size = 0;

  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required string id = 1;
    if (has_id()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->id());
    }

    // required uint64 pid = 2;
    if (has_pid()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::UInt64Size(
          this->pid());
    }

    // required uint64 vpid = 3;
    if (has_vpid()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::UInt64Size(
          this->vpid());
    }

  }
  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void container_info::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const container_info* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const container_info*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void container_info::MergeFrom(const container_info& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_id()) {
      set_id(from.id());
    }
    if (from.has_pid()) {
      set_pid(from.pid());
    }
    if (from.has_vpid()) {
      set_vpid(from.vpid());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void container_info::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void container_info::CopyFrom(const container_info& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool container_info::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000007) != 0x00000007) return false;

  return true;
}

void container_info::Swap(container_info* other) {
  if (other != this) {
    std::swap(id_, other->id_);
    std::swap(pid_, other->pid_);
    std::swap(vpid_, other->vpid_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata container_info::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = container_info_descriptor_;
  metadata.reflection = container_info_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int mounted_fs_request::kContainersFieldNumber;
#endif  // !_MSC_VER

mounted_fs_request::mounted_fs_request()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void mounted_fs_request::InitAsDefaultInstance() {
}

mounted_fs_request::mounted_fs_request(const mounted_fs_request& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void mounted_fs_request::SharedCtor() {
  _cached_size_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

mounted_fs_request::~mounted_fs_request() {
  SharedDtor();
}

void mounted_fs_request::SharedDtor() {
  if (this != default_instance_) {
  }
}

void mounted_fs_request::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* mounted_fs_request::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return mounted_fs_request_descriptor_;
}

const mounted_fs_request& mounted_fs_request::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_sdc_5finternal_2eproto();
  return *default_instance_;
}

mounted_fs_request* mounted_fs_request::default_instance_ = NULL;

mounted_fs_request* mounted_fs_request::New() const {
  return new mounted_fs_request;
}

void mounted_fs_request::Clear() {
  containers_.Clear();
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool mounted_fs_request::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // repeated .sdc_internal.container_info containers = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
         parse_containers:
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessageNoVirtual(
                input, add_containers()));
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(10)) goto parse_containers;
        if (input->ExpectAtEnd()) return true;
        break;
      }

      default: {
      handle_uninterpreted:
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          return true;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
  return true;
#undef DO_
}

void mounted_fs_request::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // repeated .sdc_internal.container_info containers = 1;
  for (int i = 0; i < this->containers_size(); i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      1, this->containers(i), output);
  }

  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* mounted_fs_request::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // repeated .sdc_internal.container_info containers = 1;
  for (int i = 0; i < this->containers_size(); i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      WriteMessageNoVirtualToArray(
        1, this->containers(i), target);
  }

  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int mounted_fs_request::ByteSize() const {
  int total_size = 0;

  // repeated .sdc_internal.container_info containers = 1;
  total_size += 1 * this->containers_size();
  for (int i = 0; i < this->containers_size(); i++) {
    total_size +=
      ::google::protobuf::internal::WireFormatLite::MessageSizeNoVirtual(
        this->containers(i));
  }

  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void mounted_fs_request::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const mounted_fs_request* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const mounted_fs_request*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void mounted_fs_request::MergeFrom(const mounted_fs_request& from) {
  GOOGLE_CHECK_NE(&from, this);
  containers_.MergeFrom(from.containers_);
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void mounted_fs_request::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void mounted_fs_request::CopyFrom(const mounted_fs_request& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool mounted_fs_request::IsInitialized() const {

  for (int i = 0; i < containers_size(); i++) {
    if (!this->containers(i).IsInitialized()) return false;
  }
  return true;
}

void mounted_fs_request::Swap(mounted_fs_request* other) {
  if (other != this) {
    containers_.Swap(&other->containers_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata mounted_fs_request::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = mounted_fs_request_descriptor_;
  metadata.reflection = mounted_fs_request_reflection_;
  return metadata;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace sdc_internal

// @@protoc_insertion_point(global_scope)
