/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/api/resource"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type WorkerAutoscalingSpec struct {
	MinReplicas *int32 `json:"minReplicas,omitempty"`
	MaxReplicas int32  `json:"maxReplicas"`
}

type WorkerSpec struct {
	Image string `json:"image,omitempty"`

	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	Autoscaling WorkerAutoscalingSpec `json:"autoscaling,omitempty"`

	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

type RedisSpec struct {
	Image string `json:"image,omitempty"`

	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	Autoscaling WorkerAutoscalingSpec `json:"autoscaling,omitempty"`
}

// ClusterSpec defines the desired state of Cluster
type ClusterSpec struct {
	Image string `json:"image,omitempty"`

	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	Replicas *int32 `json:"replicas,omitempty"`

	Domains *[]string `json:"domains,omitempty"`

	Worker WorkerSpec `json:"worker,omitempty"`

	Redis WorkerSpec `json:"redis,omitempty"`

	MaxConcurrentSessions *int32 `json:"maxConcurrentSessions,omitempty"`

	ConnectionTimeout *int64 `json:"connectionTimeout,omitempty"`

	MaxQueueLength *int32 `json:"maxQueueLength,omitempty"`

	PrebootChrome *bool `json:"prebootChrome,omitempty"`

	DemoMode *bool `json:"demoMode,omitempty"`

	UserDataStorageSize resource.Quantity `json:"userDataStorageSize,omitempty"`

	WorkspaceStorageSize resource.Quantity `json:"workspaceStorageSize,omitempty"`

	WorkspaceDeleteExpired *bool `json:"workspaceDeleteExpired,omitempty"`

	WorkspaceExpireDays *int32 `json:"workspaceExpireDays,omitempty"`

	DisableAutoSetDownloadBehavior *bool `json:"disableAutoSetDownloadBehavior,omitempty"`

	EnableDebugger *bool `json:"enableDebugger,omitempty"`

	EnableCORS *bool `json:"enableCORS,omitempty"`

	EnableXVFB *bool `json:"enableXVFB,omitempty"`

	ExitOnHealthFailure *bool `json:"exitOnHealthFailure,omitempty"`

	FunctionBuiltIns *string `json:"functionBuiltIns,omitempty"`

	FunctionExternals *string `json:"functionExternals,omitempty"`

	KeepAlive *bool `json:"keepAlive,omitempty"`

	ChromeRefreshTime *int32 `json:"chromeRefreshTime,omitempty"`

	SingleRun *bool `json:"singleRun,omitempty"`

	DefaultBlockAds *bool `json:"defaultBlockAds,omitempty"`

	DefaultHeadless *bool `json:"defaultHeadless,omitempty"`

	DefaultLaunchArgs *string `json:"defaultLaunchArgs,omitempty"`

	DefaultIgnoreHttpsErrors *bool `json:"defaultIgnoreHttpsErrors,omitempty"`

	DefaultIgnoreDefaultArgs *bool `json:"defaultIgnoreDefaultArgs,omitempty"`

	DisabledFeatures *string `json:"disabledFeatures,omitempty"`

	FunctionEnableIncognitoMode *bool `json:"functionEnableIncognitoMode,omitempty"`
}

// ClusterStatus defines the observed state of Cluster
type ClusterStatus struct {
	Concurrent *int32 `json:"concurrent,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Cluster is the Schema for the clusters API
type Cluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterSpec   `json:"spec,omitempty"`
	Status ClusterStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterList contains a list of Cluster
type ClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Cluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Cluster{}, &ClusterList{})
}
