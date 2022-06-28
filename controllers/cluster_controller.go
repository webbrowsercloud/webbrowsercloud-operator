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

package controllers

import (
	"fmt"
	"github.com/mitchellh/hashstructure/v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"context"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	webbrowsercloudv1 "webbrowsercloud/webbrowsercloud-operator/api/v1"
)

// ClusterReconciler reconciles a Cluster object
type ClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=webbrowser.cloud,resources=clusters,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=webbrowser.cloud,resources=clusters/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=webbrowser.cloud,resources=clusters/finalizers,verbs=update

//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Cluster object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.2/pkg/reconcile
func (r *ClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cluster := &webbrowsercloudv1.Cluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		logger.Error(err, "unable to fetch web browser cluster")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	secret := &corev1.Secret{}
	if err := r.GetOrCreateClusterSecret(ctx, cluster, secret); err != nil {
		logger.Error(err, "unable to fetch secret")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterServiceAccount(ctx, cluster); err != nil {
		logger.Error(err, "unable to create or update service account")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterRole(ctx, cluster); err != nil {
		logger.Error(err, "unable to create or update role")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterRoleBinding(ctx, cluster); err != nil {
		logger.Error(err, "unable to create or update role binding")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateUserDataPersistentVolumeClaim(ctx, cluster); err != nil {
		logger.Error(err, "unable to create or update user data persistent volume claim")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateWorkspacePersistentVolumeClaim(ctx, cluster); err != nil {
		logger.Error(err, "unable to create or update workspace persistent volume claim")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterService(ctx, cluster); err != nil {
		logger.Error(err, "unable to create or update service")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterIngress(ctx, cluster); err != nil {
		logger.Error(err, "unable to create or update ingress")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterDeployment(ctx, cluster, secret); err != nil {
		logger.Error(err, "unable to create or update cluster deployment")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateWorkerDeployment(ctx, cluster, secret); err != nil {
		logger.Error(err, "unable to create or update worker deployment")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&webbrowsercloudv1.Cluster{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&networkingv1.Ingress{}).
		Complete(r)
}

func (r *ClusterReconciler) GetOrCreateSecret(ctx context.Context, new *corev1.Secret, result *corev1.Secret) error {
	logger := log.FromContext(ctx)

	if err := r.Client.Get(ctx, client.ObjectKey{Name: new.Name, Namespace: new.Namespace}, result); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		if err := r.Client.Create(ctx, new); err != nil {
			return err
		}

		*result = *new
	} else {
	}

	if hash, err := hashstructure.Hash(result.Data, hashstructure.FormatV2, nil); err != nil {
		return err
	} else {
		currentHash := fmt.Sprint(hash)

		if currentHash != result.Annotations["webbrowser.cloud/last-updated-hash"] {
			if result.Annotations == nil {
				result.Annotations = map[string]string{}
			}

			result.Annotations["webbrowser.cloud/last-updated-hash"] = currentHash

			logger.Info("starting update secret hash", "hash", currentHash)

			if err := r.Update(ctx, result); err != nil {
				logger.Error(err, "unable to update secret hash")
			}
		}
	}

	return nil
}

func (r *ClusterReconciler) CreateOrUpdateService(ctx context.Context, new *corev1.Service) error {
	logger := log.FromContext(ctx)

	old := &corev1.Service{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: new.Name, Namespace: new.Namespace}, old); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		logger.Info("starting create service", "name", new.Name)

		if err := r.Client.Create(ctx, new); err != nil {
			return err
		}
	} else if !equality.Semantic.DeepDerivative(new.Spec, old.Spec) {
		old.Spec = new.Spec

		logger.Info("starting update service", "name", new.Name)

		if err := r.Client.Update(ctx, old); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterReconciler) CreateOrUpdatePersistentVolumeClaim(ctx context.Context, new *corev1.PersistentVolumeClaim) error {
	old := &corev1.PersistentVolumeClaim{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: new.Name, Namespace: new.Namespace}, old); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		if err := r.Client.Create(ctx, new); err != nil {
			return err
		}
	} else if !equality.Semantic.DeepDerivative(new.Spec.Resources.Requests, old.Spec.Resources.Requests) {
		old.Spec.Resources.Requests = new.Spec.Resources.Requests

		if err := r.Client.Update(ctx, old); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterReconciler) CreateOrUpdateDeployment(ctx context.Context, deploy *appsv1.Deployment) error {
	logger := log.FromContext(ctx)

	found := &appsv1.Deployment{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: deploy.Name, Namespace: deploy.Namespace}, found); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		logger.Info("starting create deployment", "name", deploy.Name)

		if err := r.Client.Create(ctx, deploy); err != nil {
			return err
		}
	} else if !equality.Semantic.DeepDerivative(deploy.Spec, found.Spec) {
		found.Spec = deploy.Spec

		logger.Info("starting update deployment", "name", deploy.Name)

		if err := r.Client.Update(ctx, found); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterReconciler) CreateOrUpdateRole(ctx context.Context, new *rbacv1.Role) error {
	old := &rbacv1.Role{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: new.Name, Namespace: new.Namespace}, old); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		if err := r.Client.Create(ctx, new); err != nil {
			return err
		}
	} else if !equality.Semantic.DeepDerivative(new.Rules, old.Rules) {
		old.Rules = new.Rules

		if err := r.Client.Update(ctx, old); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterReconciler) CreateOrUpdateRoleBinding(ctx context.Context, new *rbacv1.RoleBinding) error {
	old := &rbacv1.RoleBinding{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: new.Name, Namespace: new.Namespace}, old); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		if err := r.Client.Create(ctx, new); err != nil {
			return err
		}
	} else if !equality.Semantic.DeepDerivative(new.Subjects, old.Subjects) || !equality.Semantic.DeepDerivative(new.RoleRef, old.RoleRef) {
		old.Subjects = new.Subjects
		old.RoleRef = new.RoleRef

		if err := r.Client.Update(ctx, old); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterReconciler) CreateOrUpdateServiceAccount(ctx context.Context, new *corev1.ServiceAccount) error {
	old := &corev1.ServiceAccount{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: new.Name, Namespace: new.Namespace}, old); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		if err := r.Client.Create(ctx, new); err != nil {
			return err
		}
	} else if !equality.Semantic.DeepDerivative(new.Secrets, old.Secrets) {
		old.Secrets = new.Secrets

		if err := r.Client.Update(ctx, old); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterReconciler) CreateOrUpdateIngress(ctx context.Context, new *networkingv1.Ingress) error {
	old := &networkingv1.Ingress{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: new.Name, Namespace: new.Namespace}, old); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		if err := r.Client.Create(ctx, new); err != nil {
			return err
		}
	} else if !equality.Semantic.DeepDerivative(new.Spec, old.Spec) {
		old.Spec = new.Spec

		if err := r.Client.Update(ctx, old); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterReconciler) GetOrCreateClusterSecret(ctx context.Context, cluster *webbrowsercloudv1.Cluster, result *corev1.Secret) error {
	data := map[string][]byte{
		"token": []byte(""),
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
		Data: data,
	}

	return r.GetOrCreateSecret(ctx, secret, result)
}

func (r *ClusterReconciler) CreateOrUpdateClusterRole(ctx context.Context, cluster *webbrowsercloudv1.Cluster) error {
	return r.CreateOrUpdateRole(ctx, &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "watch", "list"},
		}},
	})
}

func (r *ClusterReconciler) CreateOrUpdateClusterRoleBinding(ctx context.Context, cluster *webbrowsercloudv1.Cluster) error {
	return r.CreateOrUpdateRoleBinding(ctx, &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
		Subjects: []rbacv1.Subject{{
			Kind: "ServiceAccount",
			Name: cluster.Name,
		}},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: cluster.Name,
		},
	})
}

func (r *ClusterReconciler) CreateOrUpdateClusterServiceAccount(ctx context.Context, cluster *webbrowsercloudv1.Cluster) error {
	return r.CreateOrUpdateServiceAccount(ctx, &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
	})
}

func (r *ClusterReconciler) CreateOrUpdateClusterIngress(ctx context.Context, cluster *webbrowsercloudv1.Cluster) error {
	if cluster.Spec.Domains == nil || len(*cluster.Spec.Domains) > 0 {
		r.Delete(ctx, &networkingv1.Ingress{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "networking.k8s.io/v1",
				Kind:       "Ingress",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      cluster.Name,
				Namespace: cluster.Namespace,
			},
		})

		return nil
	}

	pathType := networkingv1.PathTypePrefix

	var rules []networkingv1.IngressRule
	for _, domain := range *cluster.Spec.Domains {
		rules = append(rules, networkingv1.IngressRule{
			Host: domain,
			IngressRuleValue: networkingv1.IngressRuleValue{
				HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{
						{
							Path:     "/",
							PathType: &pathType,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: cluster.Name,
									Port: networkingv1.ServiceBackendPort{
										Name: "http",
									},
								},
							},
						},
					},
				},
			},
		})
	}

	return r.CreateOrUpdateIngress(ctx, &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "networking.k8s.io/v1",
			Kind:       "Ingress",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: rules,
		},
	})

}

func (r *ClusterReconciler) CreateOrUpdateClusterDeployment(ctx context.Context, cluster *webbrowsercloudv1.Cluster, secret *corev1.Secret) error {
	annotations := map[string]string{
		"webbrowser.cloud/secret-hash": secret.Annotations["webbrowser.cloud/last-updated-hash"],
	}

	labels := map[string]string{"cluster": cluster.Name, "component": "cluster"}

	selector := &metav1.LabelSelector{MatchLabels: labels}

	env := []corev1.EnvVar{
		{
			Name: "KUBE_NAMESPACE",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			},
		},
		{
			Name: "TOKEN",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key: "token",
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cluster.Name,
					},
				},
			},
		},
	}

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-cluster",
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: cluster.Spec.Replicas,
			Selector: selector,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
					Labels:      labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            "cluster",
							Image:           cluster.Spec.Image,
							ImagePullPolicy: cluster.Spec.ImagePullPolicy,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 3000,
									Protocol:      "TCP",
									Name:          "http",
								},
							},
							Env: env,
						},
					},
					ImagePullSecrets:   cluster.Spec.ImagePullSecrets,
					ServiceAccountName: cluster.Name,
				},
			},
		},
	}

	return r.CreateOrUpdateDeployment(ctx, deployment)
}

func (r *ClusterReconciler) CreateOrUpdateClusterService(ctx context.Context, cluster *webbrowsercloudv1.Cluster) error {
	selector := map[string]string{"cluster": cluster.Name, "component": "cluster"}

	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: selector,
			Ports: []corev1.ServicePort{{
				Name:       "http",
				Port:       80,
				Protocol:   "TCP",
				TargetPort: intstr.IntOrString{IntVal: 3000},
			}},
		},
	}

	return r.CreateOrUpdateService(ctx, service)
}

func (r *ClusterReconciler) CreateOrUpdateUserDataPersistentVolumeClaim(ctx context.Context, cluster *webbrowsercloudv1.Cluster) error {
	pvc := &corev1.PersistentVolumeClaim{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "PersistentVolumeClaim",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-userdata",
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: cluster.Spec.UserDataStorageSize,
				},
			},
		},
	}

	return r.CreateOrUpdatePersistentVolumeClaim(ctx, pvc)
}

func (r *ClusterReconciler) CreateOrUpdateWorkspacePersistentVolumeClaim(ctx context.Context, cluster *webbrowsercloudv1.Cluster) error {
	pvc := &corev1.PersistentVolumeClaim{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "PersistentVolumeClaim",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-workspace",
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: cluster.Spec.WorkspaceStorageSize,
				},
			},
		},
	}

	return r.CreateOrUpdatePersistentVolumeClaim(ctx, pvc)
}

func (r *ClusterReconciler) CreateOrUpdateWorkerDeployment(ctx context.Context, cluster *webbrowsercloudv1.Cluster, secret *corev1.Secret) error {
	annotations := map[string]string{
		"webbrowser.cloud/secret-hash": secret.Annotations["webbrowser.cloud/last-updated-hash"],
	}

	labels := map[string]string{
		"cluster":   cluster.Name,
		"component": "worker",
	}

	selector := &metav1.LabelSelector{MatchLabels: labels}

	env := []corev1.EnvVar{
		{
			Name: "HOST",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "status.podIP",
				},
			},
		},
		{
			Name: "TOKEN",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key: "token",
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cluster.Name,
					},
				},
			},
		},
		{
			Name:  "WORKSPACE_DIR",
			Value: "/workspace",
		},
	}

	if cluster.Spec.MaxConcurrentSessions != nil {
		env = append(env, corev1.EnvVar{
			Name:  "MAX_CONCURRENT_SESSIONS",
			Value: fmt.Sprint(*cluster.Spec.MaxConcurrentSessions),
		})
	}

	if cluster.Spec.ConnectionTimeout != nil {
		env = append(env, corev1.EnvVar{
			Name:  "CONNECTION_TIMEOUT",
			Value: fmt.Sprint(*cluster.Spec.ConnectionTimeout),
		})
	}

	if cluster.Spec.MaxQueueLength != nil {
		env = append(env, corev1.EnvVar{
			Name:  "MAX_QUEUE_LENGTH",
			Value: fmt.Sprint(*cluster.Spec.MaxQueueLength),
		})
	}

	if cluster.Spec.PrebootChrome != nil {
		env = append(env, corev1.EnvVar{
			Name:  "PREBOOT_CHROME",
			Value: fmt.Sprint(*cluster.Spec.PrebootChrome),
		})
	}

	if cluster.Spec.DemoMode != nil {
		env = append(env, corev1.EnvVar{
			Name:  "DEMO_MODE",
			Value: fmt.Sprint(*cluster.Spec.DemoMode),
		})
	}

	if cluster.Spec.WorkspaceDeleteExpired != nil {
		env = append(env, corev1.EnvVar{
			Name:  "WORKSPACE_DELETE_EXPIRED",
			Value: fmt.Sprint(*cluster.Spec.WorkspaceDeleteExpired),
		})
	}

	if cluster.Spec.WorkspaceExpireDays != nil {
		env = append(env, corev1.EnvVar{
			Name:  "WORKSPACE_EXPIRE_DAYS",
			Value: fmt.Sprint(*cluster.Spec.WorkspaceExpireDays),
		})
	}

	if cluster.Spec.EnableDebugger != nil {
		env = append(env, corev1.EnvVar{
			Name:  "ENABLE_DEBUGGER",
			Value: fmt.Sprint(*cluster.Spec.EnableDebugger),
		})
	}

	if cluster.Spec.DisableAutoSetDownloadBehavior != nil {
		env = append(env, corev1.EnvVar{
			Name:  "DISABLE_AUTO_SET_DOWNLOAD_BEHAVIOR",
			Value: fmt.Sprint(*cluster.Spec.DisableAutoSetDownloadBehavior),
		})
	}

	if cluster.Spec.EnableCORS != nil {
		env = append(env, corev1.EnvVar{
			Name:  "ENABLE_CORS",
			Value: fmt.Sprint(*cluster.Spec.EnableCORS),
		})
	}

	if cluster.Spec.EnableXVFB != nil {
		env = append(env, corev1.EnvVar{
			Name:  "ENABLE_XVFB",
			Value: fmt.Sprint(*cluster.Spec.EnableXVFB),
		})
	}

	if cluster.Spec.ExitOnHealthFailure != nil {
		env = append(env, corev1.EnvVar{
			Name:  "EXIT_ON_HEALTH_FAILURE",
			Value: fmt.Sprint(*cluster.Spec.ExitOnHealthFailure),
		})
	}

	if cluster.Spec.FunctionBuiltIns != nil {
		env = append(env, corev1.EnvVar{
			Name:  "FUNCTION_BUILT_INS",
			Value: *cluster.Spec.FunctionBuiltIns,
		})
	}

	if cluster.Spec.FunctionExternals != nil {
		env = append(env, corev1.EnvVar{
			Name:  "FUNCTION_EXTERNALS",
			Value: *cluster.Spec.FunctionExternals,
		})
	}

	if cluster.Spec.KeepAlive != nil {
		env = append(env, corev1.EnvVar{
			Name:  "KEEP_ALIVE",
			Value: fmt.Sprint(*cluster.Spec.KeepAlive),
		})
	}

	if cluster.Spec.DefaultBlockAds != nil {
		env = append(env, corev1.EnvVar{
			Name:  "DEFAULT_BLOCK_ADS",
			Value: fmt.Sprint(*cluster.Spec.DefaultBlockAds),
		})
	}

	if cluster.Spec.DefaultHeadless != nil {
		env = append(env, corev1.EnvVar{
			Name:  "DEFAULT_HEADLESS",
			Value: fmt.Sprint(*cluster.Spec.DefaultHeadless),
		})
	}

	if cluster.Spec.DefaultLaunchArgs != nil {
		env = append(env, corev1.EnvVar{
			Name:  "DEFAULT_LAUNCH_ARGS",
			Value: *cluster.Spec.DefaultLaunchArgs,
		})
	}

	if cluster.Spec.DefaultIgnoreHttpsErrors != nil {
		env = append(env, corev1.EnvVar{
			Name:  "DEFAULT_IGNORE_HTTPS_ERRORS",
			Value: fmt.Sprint(*cluster.Spec.DefaultIgnoreHttpsErrors),
		})
	}

	if cluster.Spec.DefaultIgnoreDefaultArgs != nil {
		env = append(env, corev1.EnvVar{
			Name:  "DEFAULT_IGNORE_DEFAULT_ARGS",
			Value: fmt.Sprint(*cluster.Spec.DefaultIgnoreDefaultArgs),
		})
	}

	if cluster.Spec.DisabledFeatures != nil {
		env = append(env, corev1.EnvVar{
			Name:  "DISABLED_FEATURES",
			Value: *cluster.Spec.DisabledFeatures,
		})
	}

	if cluster.Spec.FunctionEnableIncognitoMode != nil {
		env = append(env, corev1.EnvVar{
			Name:  "FUNCTION_ENABLE_INCOGNITO_MODE",
			Value: fmt.Sprint(*cluster.Spec.FunctionEnableIncognitoMode),
		})
	}

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name + "-worker",
			Namespace: cluster.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(cluster, schema.GroupVersionKind{
					Group:   webbrowsercloudv1.GroupVersion.Group,
					Version: webbrowsercloudv1.GroupVersion.Version,
					Kind:    cluster.Kind,
				}),
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: cluster.Spec.Worker.Autoscaling.MinReplicas,
			Selector: selector,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: annotations,
					Labels:      labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            "worker",
							Image:           cluster.Spec.Worker.Image,
							ImagePullPolicy: cluster.Spec.Worker.ImagePullPolicy,
							Resources:       cluster.Spec.Worker.Resources,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 3000,
									Protocol:      "TCP",
									Name:          "http",
								},
							},
							Env: env,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "userdata",
									MountPath: "/userdata",
								},
								{
									Name:      "workspace",
									MountPath: "/workspace",
								},
							},
						},
					},
					ImagePullSecrets: cluster.Spec.Worker.ImagePullSecrets,
					Volumes: []corev1.Volume{
						{
							Name: "userdata",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: cluster.Name + "-userdata",
								},
							},
						},
						{
							Name: "workspace",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: cluster.Name + "-workspace",
								},
							},
						},
					},
				},
			},
		},
	}

	return r.CreateOrUpdateDeployment(ctx, deployment)
}
