(function() {var implementors = {};
implementors["arc_swap"] = [{"text":"impl&lt;T&gt; Deref for DirectDeref&lt;Arc&lt;T&gt;&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Deref for DirectDeref&lt;Rc&lt;T&gt;&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;?Sized&gt; Deref for DynGuard&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;G, T&gt; Deref for MapGuard&lt;G, T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Deref for ConstantDeref&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;'a, T:&nbsp;RefCnt&gt; Deref for Guard&lt;'a, T&gt;","synthetic":false,"types":[]}];
implementors["bytes"] = [{"text":"impl Deref for Bytes","synthetic":false,"types":[]},{"text":"impl Deref for BytesMut","synthetic":false,"types":[]}];
implementors["futures_executor"] = [{"text":"impl&lt;S:&nbsp;Stream + Unpin&gt; Deref for BlockingStream&lt;S&gt;","synthetic":false,"types":[]}];
implementors["futures_task"] = [{"text":"impl Deref for WakerRef&lt;'_&gt;","synthetic":false,"types":[]}];
implementors["futures_util"] = [{"text":"impl&lt;T:&nbsp;?Sized&gt; Deref for MutexGuard&lt;'_, T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;?Sized, U:&nbsp;?Sized&gt; Deref for MappedMutexGuard&lt;'_, T, U&gt;","synthetic":false,"types":[]}];
implementors["iovec"] = [{"text":"impl Deref for IoVec","synthetic":false,"types":[]}];
implementors["mio"] = [{"text":"impl Deref for UnixReady","synthetic":false,"types":[]}];
implementors["once_cell"] = [{"text":"impl&lt;T, F:&nbsp;FnOnce() -&gt; T&gt; Deref for Lazy&lt;T, F&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T, F:&nbsp;FnOnce() -&gt; T&gt; Deref for Lazy&lt;T, F&gt;","synthetic":false,"types":[]}];
implementors["syn"] = [{"text":"impl Deref for Underscore","synthetic":false,"types":[]},{"text":"impl Deref for Add","synthetic":false,"types":[]},{"text":"impl Deref for And","synthetic":false,"types":[]},{"text":"impl Deref for At","synthetic":false,"types":[]},{"text":"impl Deref for Bang","synthetic":false,"types":[]},{"text":"impl Deref for Caret","synthetic":false,"types":[]},{"text":"impl Deref for Colon","synthetic":false,"types":[]},{"text":"impl Deref for Comma","synthetic":false,"types":[]},{"text":"impl Deref for Div","synthetic":false,"types":[]},{"text":"impl Deref for Dollar","synthetic":false,"types":[]},{"text":"impl Deref for Dot","synthetic":false,"types":[]},{"text":"impl Deref for Eq","synthetic":false,"types":[]},{"text":"impl Deref for Gt","synthetic":false,"types":[]},{"text":"impl Deref for Lt","synthetic":false,"types":[]},{"text":"impl Deref for Or","synthetic":false,"types":[]},{"text":"impl Deref for Pound","synthetic":false,"types":[]},{"text":"impl Deref for Question","synthetic":false,"types":[]},{"text":"impl Deref for Rem","synthetic":false,"types":[]},{"text":"impl Deref for Semi","synthetic":false,"types":[]},{"text":"impl Deref for Star","synthetic":false,"types":[]},{"text":"impl Deref for Sub","synthetic":false,"types":[]},{"text":"impl Deref for Tilde","synthetic":false,"types":[]},{"text":"impl&lt;'c, 'a&gt; Deref for StepCursor&lt;'c, 'a&gt;","synthetic":false,"types":[]}];
implementors["tokio"] = [{"text":"impl&lt;T:&nbsp;?Sized&gt; Deref for MutexGuard&lt;'_, T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;?Sized&gt; Deref for OwnedMutexGuard&lt;T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;?Sized&gt; Deref for RwLockReadGuard&lt;'_, T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T:&nbsp;?Sized&gt; Deref for RwLockWriteGuard&lt;'_, T&gt;","synthetic":false,"types":[]},{"text":"impl&lt;T&gt; Deref for Ref&lt;'_, T&gt;","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()