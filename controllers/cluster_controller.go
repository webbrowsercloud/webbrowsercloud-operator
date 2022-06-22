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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete

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
	log := log.FromContext(ctx)

	cluster := &webbrowsercloudv1.Cluster{}
	if err := r.Get(ctx, req.NamespacedName, cluster); err != nil {
		log.Error(err, "unable to fetch web browser cluster")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterServiceAccount(ctx, cluster); err != nil {
		log.Error(err, "unable to create or update service account")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterRole(ctx, cluster); err != nil {
		log.Error(err, "unable to create or update role")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterRoleBinding(ctx, cluster); err != nil {
		log.Error(err, "unable to create or update role binding")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterDeployment(ctx, cluster); err != nil {
		log.Error(err, "unable to create or update cluster deployment")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateClusterService(ctx, cluster); err != nil {
		log.Error(err, "unable to create or update cluster service")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.CreateOrUpdateWorkerDeployment(ctx, cluster); err != nil {
		log.Error(err, "unable to create or update worker deployment")

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
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Complete(r)
}

func (r *ClusterReconciler) CreateOrUpdateDeployment(ctx context.Context, deploy *appsv1.Deployment) error {
	found := &appsv1.Deployment{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: deploy.Name, Namespace: deploy.Namespace}, found); err != nil {
		if !errors.IsNotFound(err) {
			return err
		}

		if err := r.Client.Create(ctx, deploy); err != nil {
			return err
		}
	} else if !equality.Semantic.DeepDerivative(deploy.Spec, found.Spec) {
		found.Spec = deploy.Spec

		if err := r.Client.Update(ctx, found); err != nil {
			return err
		}
	}

	return nil
}

func (r *ClusterReconciler) CreateOrUpdateService(ctx context.Context, new *corev1.Service) error {
	old := &corev1.Service{}
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

func (r *ClusterReconciler) CreateOrUpdateClusterDeployment(ctx context.Context, cluster *webbrowsercloudv1.Cluster) error {
	labels := map[string]string{"cluster": cluster.Name, "component": "cluster"}

	selector := &metav1.LabelSelector{MatchLabels: labels}

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
			Selector: selector,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            cluster.Name,
							Image:           cluster.Spec.Image,
							ImagePullPolicy: cluster.Spec.ImagePullPolicy,
							Ports: []corev1.ContainerPort{
								{
									Protocol:      "TCP",
									ContainerPort: 3000,
									HostPort:      3000,
								},
							},
							Env: []corev1.EnvVar{
								{
									Name: "KUBE_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
							},
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

func (r *ClusterReconciler) CreateOrUpdateWorkerDeployment(ctx context.Context, cluster *webbrowsercloudv1.Cluster) error {
	labels := map[string]string{"cluster": cluster.Name, "component": "worker"}

	selector := &metav1.LabelSelector{MatchLabels: labels}

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
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            cluster.Name,
							Image:           cluster.Spec.Worker.Image,
							ImagePullPolicy: cluster.Spec.Worker.ImagePullPolicy,
							Resources:       cluster.Spec.Worker.Resources,
							Ports: []corev1.ContainerPort{
								{
									Protocol:      "TCP",
									ContainerPort: 3000,
									HostPort:      3000,
								},
							},
						},
					},
					ImagePullSecrets: cluster.Spec.Worker.ImagePullSecrets,
				},
			},
		},
	}

	return r.CreateOrUpdateDeployment(ctx, deployment)
}
