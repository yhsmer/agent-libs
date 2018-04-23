package kubecollect

import (
	"cointerface/draiosproto"
	"context"
	"sync"
	"github.com/gogo/protobuf/proto"
	log "github.com/cihub/seelog"
	kubeclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/api/core/v1"
)

// make this a library function?
func replicationControllerEvent(rc *v1.ReplicationController, eventType *draiosproto.CongroupEventType) (draiosproto.CongroupUpdateEvent) {
	return draiosproto.CongroupUpdateEvent {
		Type: eventType,
		Object: newReplicationControllerCongroup(rc),
	}
}

func newReplicationControllerCongroup(replicationController *v1.ReplicationController) (*draiosproto.ContainerGroup) {
	ret := &draiosproto.ContainerGroup{
		Uid: &draiosproto.CongroupUid{
			Kind:proto.String("k8s_replicationcontroller"),
			Id:proto.String(string(replicationController.GetUID()))},
	}

	ret.Tags = GetTags(replicationController.ObjectMeta, "kubernetes.replicationController.")
	ret.InternalTags = GetAnnotations(replicationController.ObjectMeta, "kubernetes.replicationController.")
	addReplicationControllerMetrics(&ret.Metrics, replicationController)
	AddNSParents(&ret.Parents, replicationController.GetNamespace())
	selector := labels.Set(replicationController.Spec.Selector).AsSelector()
	AddPodChildren(&ret.Children, selector, replicationController.GetNamespace())
	AddHorizontalPodAutoscalerParents(&ret.Parents, replicationController.GetNamespace(), replicationController.APIVersion, replicationController.Kind, replicationController.GetName() )

	return ret
}

var replicationControllerInf cache.SharedInformer

func addReplicationControllerMetrics(metrics *[]*draiosproto.AppMetric, replicationController *v1.ReplicationController) {
	prefix := "kubernetes.replicationController."
	AppendMetricInt32(metrics, prefix+"status.replicas", replicationController.Status.Replicas)
	AppendMetricInt32(metrics, prefix+"status.fullyLabeledReplicas", replicationController.Status.FullyLabeledReplicas)
	AppendMetricInt32(metrics, prefix+"status.readyReplicas", replicationController.Status.ReadyReplicas)
	AppendMetricInt32(metrics, prefix+"status.availableReplicas", replicationController.Status.AvailableReplicas)
	AppendMetricPtrInt32(metrics, prefix+"spec.replicas", replicationController.Spec.Replicas)
}

func AddReplicationControllerParents(parents *[]*draiosproto.CongroupUid, pod *v1.Pod) {
	if !resourceReady("replicationcontrollers") {
		return
	}

	for _, obj := range replicationControllerInf.GetStore().List() {
		replicationController := obj.(*v1.ReplicationController)
		//log.Debugf("AddNSParents: %v", nsObj.GetName())
		selector := labels.Set(replicationController.Spec.Selector).AsSelector()
		if pod.GetNamespace() == replicationController.GetNamespace() && selector.Matches(labels.Set(pod.GetLabels())) {
			*parents = append(*parents, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicationcontroller"),
				Id:proto.String(string(replicationController.GetUID()))})
		}
	}
}

func AddReplicationControllerChildrenFromNamespace(children *[]*draiosproto.CongroupUid, namespaceName string) {
	if !resourceReady("replicationcontrollers") {
		return
	}

	for _, obj := range replicationControllerInf.GetStore().List() {
		replicationController := obj.(*v1.ReplicationController)
		if replicationController.GetNamespace() == namespaceName {
			*children = append(*children, &draiosproto.CongroupUid{
					Kind:proto.String("k8s_replicationcontroller"),
				Id:proto.String(string(replicationController.GetUID()))})
		}
	}
}

func AddReplicationControllerChildrenByName(children *[]*draiosproto.CongroupUid, namespace string, name string) {
	if !resourceReady("replicationcontrollers") {
		return
	}

	for _, obj := range replicationControllerInf.GetStore().List() {
		rc := obj.(*v1.ReplicationController)
		if (rc.GetNamespace() == namespace) &&
			(rc.GetName() == name) {
			*children = append(*children, &draiosproto.CongroupUid{
				Kind:proto.String("k8s_replicationcontroller"),
				Id:proto.String(string(rc.GetUID()))})
		}
	}
}

func startReplicationControllersSInformer(ctx context.Context, kubeClient kubeclient.Interface, wg *sync.WaitGroup, evtc chan<- draiosproto.CongroupUpdateEvent) {
	client := kubeClient.CoreV1().RESTClient()
	lw := cache.NewListWatchFromClient(client, "ReplicationControllers", v1meta.NamespaceAll, fields.Everything())
	replicationControllerInf = cache.NewSharedInformer(lw, &v1.ReplicationController{}, RsyncInterval)

	wg.Add(1)
	go func() {
		watchReplicationControllers(evtc)
		replicationControllerInf.Run(ctx.Done())
		wg.Done()
	}()
}

func watchReplicationControllers(evtc chan<- draiosproto.CongroupUpdateEvent) {
	log.Debugf("In WatchReplicationControllers()")

	replicationControllerInf.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				eventReceived("replicationcontrollers")
				//log.Debugf("AddFunc dumping ReplicationController: %v", obj.(*v1.ReplicationController))
				evtc <- replicationControllerEvent(obj.(*v1.ReplicationController),
					draiosproto.CongroupEventType_ADDED.Enum())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldReplicationController := oldObj.(*v1.ReplicationController)
				newReplicationController := newObj.(*v1.ReplicationController)
				if oldReplicationController.GetResourceVersion() != newReplicationController.GetResourceVersion() {
					//log.Debugf("UpdateFunc dumping ReplicationController oldReplicationController %v", oldReplicationController)
					//log.Debugf("UpdateFunc dumping ReplicationController newReplicationController %v", newReplicationController)
					evtc <- replicationControllerEvent(newReplicationController,
						draiosproto.CongroupEventType_UPDATED.Enum())
				}
			},
			DeleteFunc: func(obj interface{}) {
				//log.Debugf("DeleteFunc dumping ReplicationController: %v", obj.(*v1.ReplicationController))
				evtc <- replicationControllerEvent(obj.(*v1.ReplicationController),
					draiosproto.CongroupEventType_REMOVED.Enum())
			},
		},
	)
}
