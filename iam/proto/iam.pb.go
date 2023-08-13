// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: iam/proto/iam.proto

package cmproto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ActionPayload struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id          string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name        string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Displayname string `protobuf:"bytes,3,opt,name=displayname,proto3" json:"displayname,omitempty"`
	Serviceid   string `protobuf:"bytes,4,opt,name=serviceid,proto3" json:"serviceid,omitempty"`
}

func (x *ActionPayload) Reset() {
	*x = ActionPayload{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ActionPayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ActionPayload) ProtoMessage() {}

func (x *ActionPayload) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ActionPayload.ProtoReflect.Descriptor instead.
func (*ActionPayload) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{0}
}

func (x *ActionPayload) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *ActionPayload) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ActionPayload) GetDisplayname() string {
	if x != nil {
		return x.Displayname
	}
	return ""
}

func (x *ActionPayload) GetServiceid() string {
	if x != nil {
		return x.Serviceid
	}
	return ""
}

type RegisterActionsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Actions []*ActionPayload `protobuf:"bytes,1,rep,name=actions,proto3" json:"actions,omitempty"`
}

func (x *RegisterActionsRequest) Reset() {
	*x = RegisterActionsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegisterActionsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterActionsRequest) ProtoMessage() {}

func (x *RegisterActionsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterActionsRequest.ProtoReflect.Descriptor instead.
func (*RegisterActionsRequest) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{1}
}

func (x *RegisterActionsRequest) GetActions() []*ActionPayload {
	if x != nil {
		return x.Actions
	}
	return nil
}

type ActionIds struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Actionid string `protobuf:"bytes,1,opt,name=actionid,proto3" json:"actionid,omitempty"`
}

func (x *ActionIds) Reset() {
	*x = ActionIds{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ActionIds) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ActionIds) ProtoMessage() {}

func (x *ActionIds) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ActionIds.ProtoReflect.Descriptor instead.
func (*ActionIds) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{2}
}

func (x *ActionIds) GetActionid() string {
	if x != nil {
		return x.Actionid
	}
	return ""
}

type RegisterActionsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Actionids []*ActionIds `protobuf:"bytes,1,rep,name=actionids,proto3" json:"actionids,omitempty"`
}

func (x *RegisterActionsResponse) Reset() {
	*x = RegisterActionsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegisterActionsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterActionsResponse) ProtoMessage() {}

func (x *RegisterActionsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterActionsResponse.ProtoReflect.Descriptor instead.
func (*RegisterActionsResponse) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{3}
}

func (x *RegisterActionsResponse) GetActionids() []*ActionIds {
	if x != nil {
		return x.Actionids
	}
	return nil
}

type RolePayload struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id          string   `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Actionid    []string `protobuf:"bytes,2,rep,name=actionid,proto3" json:"actionid,omitempty"`
	Rolename    string   `protobuf:"bytes,3,opt,name=rolename,proto3" json:"rolename,omitempty"`
	Displayname string   `protobuf:"bytes,4,opt,name=displayname,proto3" json:"displayname,omitempty"`
	Owner       string   `protobuf:"bytes,5,opt,name=owner,proto3" json:"owner,omitempty"`
	Description string   `protobuf:"bytes,6,opt,name=description,proto3" json:"description,omitempty"`
	Serviceid   string   `protobuf:"bytes,7,opt,name=serviceid,proto3" json:"serviceid,omitempty"`
}

func (x *RolePayload) Reset() {
	*x = RolePayload{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RolePayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RolePayload) ProtoMessage() {}

func (x *RolePayload) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RolePayload.ProtoReflect.Descriptor instead.
func (*RolePayload) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{4}
}

func (x *RolePayload) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *RolePayload) GetActionid() []string {
	if x != nil {
		return x.Actionid
	}
	return nil
}

func (x *RolePayload) GetRolename() string {
	if x != nil {
		return x.Rolename
	}
	return ""
}

func (x *RolePayload) GetDisplayname() string {
	if x != nil {
		return x.Displayname
	}
	return ""
}

func (x *RolePayload) GetOwner() string {
	if x != nil {
		return x.Owner
	}
	return ""
}

func (x *RolePayload) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *RolePayload) GetServiceid() string {
	if x != nil {
		return x.Serviceid
	}
	return ""
}

type RegisterRolesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Roles []*RolePayload `protobuf:"bytes,1,rep,name=roles,proto3" json:"roles,omitempty"`
}

func (x *RegisterRolesRequest) Reset() {
	*x = RegisterRolesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegisterRolesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterRolesRequest) ProtoMessage() {}

func (x *RegisterRolesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterRolesRequest.ProtoReflect.Descriptor instead.
func (*RegisterRolesRequest) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{5}
}

func (x *RegisterRolesRequest) GetRoles() []*RolePayload {
	if x != nil {
		return x.Roles
	}
	return nil
}

type RegisterRolesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Success bool `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
}

func (x *RegisterRolesResponse) Reset() {
	*x = RegisterRolesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RegisterRolesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RegisterRolesResponse) ProtoMessage() {}

func (x *RegisterRolesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RegisterRolesResponse.ProtoReflect.Descriptor instead.
func (*RegisterRolesResponse) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{6}
}

func (x *RegisterRolesResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

type FetchServiceByNameRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *FetchServiceByNameRequest) Reset() {
	*x = FetchServiceByNameRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FetchServiceByNameRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FetchServiceByNameRequest) ProtoMessage() {}

func (x *FetchServiceByNameRequest) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FetchServiceByNameRequest.ProtoReflect.Descriptor instead.
func (*FetchServiceByNameRequest) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{7}
}

func (x *FetchServiceByNameRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type FetchServiceByNameResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id                 string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	ServiceName        string `protobuf:"bytes,2,opt,name=serviceName,proto3" json:"serviceName,omitempty"`
	ServiceDescription string `protobuf:"bytes,3,opt,name=serviceDescription,proto3" json:"serviceDescription,omitempty"`
	Version            int32  `protobuf:"varint,4,opt,name=Version,proto3" json:"Version,omitempty"`
}

func (x *FetchServiceByNameResponse) Reset() {
	*x = FetchServiceByNameResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FetchServiceByNameResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FetchServiceByNameResponse) ProtoMessage() {}

func (x *FetchServiceByNameResponse) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FetchServiceByNameResponse.ProtoReflect.Descriptor instead.
func (*FetchServiceByNameResponse) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{8}
}

func (x *FetchServiceByNameResponse) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *FetchServiceByNameResponse) GetServiceName() string {
	if x != nil {
		return x.ServiceName
	}
	return ""
}

func (x *FetchServiceByNameResponse) GetServiceDescription() string {
	if x != nil {
		return x.ServiceDescription
	}
	return ""
}

func (x *FetchServiceByNameResponse) GetVersion() int32 {
	if x != nil {
		return x.Version
	}
	return 0
}

type UpdateServiceVersionRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Servicename string `protobuf:"bytes,1,opt,name=servicename,proto3" json:"servicename,omitempty"`
	Version     int32  `protobuf:"varint,2,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *UpdateServiceVersionRequest) Reset() {
	*x = UpdateServiceVersionRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateServiceVersionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateServiceVersionRequest) ProtoMessage() {}

func (x *UpdateServiceVersionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateServiceVersionRequest.ProtoReflect.Descriptor instead.
func (*UpdateServiceVersionRequest) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{9}
}

func (x *UpdateServiceVersionRequest) GetServicename() string {
	if x != nil {
		return x.Servicename
	}
	return ""
}

func (x *UpdateServiceVersionRequest) GetVersion() int32 {
	if x != nil {
		return x.Version
	}
	return 0
}

type UpdateServiceVersionResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Success bool `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
}

func (x *UpdateServiceVersionResponse) Reset() {
	*x = UpdateServiceVersionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_iam_proto_iam_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateServiceVersionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateServiceVersionResponse) ProtoMessage() {}

func (x *UpdateServiceVersionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_iam_proto_iam_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateServiceVersionResponse.ProtoReflect.Descriptor instead.
func (*UpdateServiceVersionResponse) Descriptor() ([]byte, []int) {
	return file_iam_proto_iam_proto_rawDescGZIP(), []int{10}
}

func (x *UpdateServiceVersionResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

var File_iam_proto_iam_proto protoreflect.FileDescriptor

var file_iam_proto_iam_proto_rawDesc = []byte{
	0x0a, 0x13, 0x69, 0x61, 0x6d, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x69, 0x61, 0x6d, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x43, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x22, 0x73, 0x0a, 0x0d, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61,
	0x64, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69,
	0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x70,
	0x6c, 0x61, 0x79, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x69, 0x64, 0x22, 0x4c, 0x0a, 0x16, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65,
	0x72, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x32, 0x0a, 0x07, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x18, 0x2e, 0x43, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x41, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x52, 0x07, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x22, 0x27, 0x0a, 0x09, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x73,
	0x12, 0x1a, 0x0a, 0x08, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x69, 0x64, 0x22, 0x4d, 0x0a, 0x17,
	0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x32, 0x0a, 0x09, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x69, 0x64, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x43, 0x6d, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x73,
	0x52, 0x09, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x69, 0x64, 0x73, 0x22, 0xcd, 0x01, 0x0a, 0x0b,
	0x52, 0x6f, 0x6c, 0x65, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x0e, 0x0a, 0x02, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x69, 0x64, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x61,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x69, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x72, 0x6f, 0x6c, 0x65, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72, 0x6f, 0x6c, 0x65, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61,
	0x79, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x12, 0x20, 0x0a, 0x0b, 0x64,
	0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a,
	0x09, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x69, 0x64, 0x22, 0x44, 0x0a, 0x14, 0x52,
	0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x52, 0x6f, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x2c, 0x0a, 0x05, 0x72, 0x6f, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x16, 0x2e, 0x43, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x52,
	0x6f, 0x6c, 0x65, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x52, 0x05, 0x72, 0x6f, 0x6c, 0x65,
	0x73, 0x22, 0x31, 0x0a, 0x15, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x52, 0x6f, 0x6c,
	0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x75,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x73, 0x75, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x22, 0x2f, 0x0a, 0x19, 0x46, 0x65, 0x74, 0x63, 0x68, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x42, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x98, 0x01, 0x0a, 0x1a, 0x46, 0x65, 0x74, 0x63, 0x68, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x42, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x69, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x4e,
	0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x2e, 0x0a, 0x12, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x12, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x44, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x22, 0x59, 0x0a, 0x1b, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x20, 0x0a, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x38, 0x0a, 0x1c, 0x55,
	0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x56, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x73,
	0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x73, 0x75,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x32, 0x88, 0x03, 0x0a, 0x0c, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x12, 0x58, 0x0a, 0x0f, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74,
	0x65, 0x72, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x21, 0x2e, 0x43, 0x6d, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x41, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x22, 0x2e, 0x43,
	0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65,
	0x72, 0x41, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x52, 0x0a, 0x0d, 0x52, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x52, 0x6f, 0x6c, 0x65,
	0x73, 0x12, 0x1f, 0x2e, 0x43, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x52, 0x65,
	0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x52, 0x6f, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x20, 0x2e, 0x43, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x52,
	0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x52, 0x6f, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x61, 0x0a, 0x12, 0x46, 0x65, 0x74, 0x63, 0x68, 0x53, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x42, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x24, 0x2e, 0x43, 0x6d, 0x53,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x46, 0x65, 0x74, 0x63, 0x68, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x42, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x25, 0x2e, 0x43, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x46, 0x65, 0x74,
	0x63, 0x68, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x42, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x67, 0x0a, 0x14, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x26, 0x2e, 0x43, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x27, 0x2e, 0x43, 0x6d, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x42, 0x2b, 0x5a, 0x29, 0x67, 0x69, 0x74, 0x6c, 0x61, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74,
	0x61, 0x72, 0x69, 0x61, 0x6e, 0x64, 0x65, 0x76, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x6c, 0x6f, 0x70,
	0x73, 0x2f, 0x69, 0x61, 0x6d, 0x2f, 0x63, 0x6d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_iam_proto_iam_proto_rawDescOnce sync.Once
	file_iam_proto_iam_proto_rawDescData = file_iam_proto_iam_proto_rawDesc
)

func file_iam_proto_iam_proto_rawDescGZIP() []byte {
	file_iam_proto_iam_proto_rawDescOnce.Do(func() {
		file_iam_proto_iam_proto_rawDescData = protoimpl.X.CompressGZIP(file_iam_proto_iam_proto_rawDescData)
	})
	return file_iam_proto_iam_proto_rawDescData
}

var file_iam_proto_iam_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_iam_proto_iam_proto_goTypes = []interface{}{
	(*ActionPayload)(nil),                // 0: CmService.ActionPayload
	(*RegisterActionsRequest)(nil),       // 1: CmService.RegisterActionsRequest
	(*ActionIds)(nil),                    // 2: CmService.ActionIds
	(*RegisterActionsResponse)(nil),      // 3: CmService.RegisterActionsResponse
	(*RolePayload)(nil),                  // 4: CmService.RolePayload
	(*RegisterRolesRequest)(nil),         // 5: CmService.RegisterRolesRequest
	(*RegisterRolesResponse)(nil),        // 6: CmService.RegisterRolesResponse
	(*FetchServiceByNameRequest)(nil),    // 7: CmService.FetchServiceByNameRequest
	(*FetchServiceByNameResponse)(nil),   // 8: CmService.FetchServiceByNameResponse
	(*UpdateServiceVersionRequest)(nil),  // 9: CmService.UpdateServiceVersionRequest
	(*UpdateServiceVersionResponse)(nil), // 10: CmService.UpdateServiceVersionResponse
}
var file_iam_proto_iam_proto_depIdxs = []int32{
	0,  // 0: CmService.RegisterActionsRequest.actions:type_name -> CmService.ActionPayload
	2,  // 1: CmService.RegisterActionsResponse.actionids:type_name -> CmService.ActionIds
	4,  // 2: CmService.RegisterRolesRequest.roles:type_name -> CmService.RolePayload
	1,  // 3: CmService.CommonModule.RegisterActions:input_type -> CmService.RegisterActionsRequest
	5,  // 4: CmService.CommonModule.RegisterRoles:input_type -> CmService.RegisterRolesRequest
	7,  // 5: CmService.CommonModule.FetchServiceByName:input_type -> CmService.FetchServiceByNameRequest
	9,  // 6: CmService.CommonModule.UpdateServiceVersion:input_type -> CmService.UpdateServiceVersionRequest
	3,  // 7: CmService.CommonModule.RegisterActions:output_type -> CmService.RegisterActionsResponse
	6,  // 8: CmService.CommonModule.RegisterRoles:output_type -> CmService.RegisterRolesResponse
	8,  // 9: CmService.CommonModule.FetchServiceByName:output_type -> CmService.FetchServiceByNameResponse
	10, // 10: CmService.CommonModule.UpdateServiceVersion:output_type -> CmService.UpdateServiceVersionResponse
	7,  // [7:11] is the sub-list for method output_type
	3,  // [3:7] is the sub-list for method input_type
	3,  // [3:3] is the sub-list for extension type_name
	3,  // [3:3] is the sub-list for extension extendee
	0,  // [0:3] is the sub-list for field type_name
}

func init() { file_iam_proto_iam_proto_init() }
func file_iam_proto_iam_proto_init() {
	if File_iam_proto_iam_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_iam_proto_iam_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ActionPayload); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegisterActionsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ActionIds); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegisterActionsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RolePayload); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegisterRolesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RegisterRolesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FetchServiceByNameRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FetchServiceByNameResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateServiceVersionRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_iam_proto_iam_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateServiceVersionResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_iam_proto_iam_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_iam_proto_iam_proto_goTypes,
		DependencyIndexes: file_iam_proto_iam_proto_depIdxs,
		MessageInfos:      file_iam_proto_iam_proto_msgTypes,
	}.Build()
	File_iam_proto_iam_proto = out.File
	file_iam_proto_iam_proto_rawDesc = nil
	file_iam_proto_iam_proto_goTypes = nil
	file_iam_proto_iam_proto_depIdxs = nil
}
