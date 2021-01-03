(function() {var implementors = {};
implementors["bytes"] = [{"text":"impl FromIterator&lt;u8&gt; for Bytes","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;u8&gt; for BytesMut","synthetic":false,"types":[]},{"text":"impl&lt;'a&gt; FromIterator&lt;&amp;'a u8&gt; for BytesMut","synthetic":false,"types":[]}];
implementors["futures_util"] = [{"text":"impl&lt;F:&nbsp;Future&gt; FromIterator&lt;F&gt; for JoinAll&lt;F&gt;","synthetic":false,"types":[]},{"text":"impl&lt;Fut:&nbsp;Future + Unpin&gt; FromIterator&lt;Fut&gt; for SelectAll&lt;Fut&gt;","synthetic":false,"types":[]},{"text":"impl&lt;F:&nbsp;TryFuture&gt; FromIterator&lt;F&gt; for TryJoinAll&lt;F&gt;","synthetic":false,"types":[]},{"text":"impl&lt;Fut:&nbsp;TryFuture + Unpin&gt; FromIterator&lt;Fut&gt; for SelectOk&lt;Fut&gt;","synthetic":false,"types":[]},{"text":"impl&lt;Fut:&nbsp;Future&gt; FromIterator&lt;Fut&gt; for FuturesOrdered&lt;Fut&gt;","synthetic":false,"types":[]},{"text":"impl&lt;Fut&gt; FromIterator&lt;Fut&gt; for FuturesUnordered&lt;Fut&gt;","synthetic":false,"types":[]},{"text":"impl&lt;St:&nbsp;Stream + Unpin&gt; FromIterator&lt;St&gt; for SelectAll&lt;St&gt;","synthetic":false,"types":[]}];
implementors["nix"] = [{"text":"impl FromIterator&lt;AtFlags&gt; for AtFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;OFlag&gt; for OFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;SealFlag&gt; for SealFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;FdFlag&gt; for FdFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;SpliceFFlags&gt; for SpliceFFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;FallocateFlags&gt; for FallocateFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;ModuleInitFlags&gt; for ModuleInitFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;DeleteModuleFlags&gt; for DeleteModuleFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;MsFlags&gt; for MsFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;MntFlags&gt; for MntFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;MQ_OFlag&gt; for MQ_OFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;FdFlag&gt; for FdFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;InterfaceFlags&gt; for InterfaceFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;PollFlags&gt; for PollFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;CloneFlags&gt; for CloneFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;EpollFlags&gt; for EpollFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;EpollCreateFlags&gt; for EpollCreateFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;EfdFlags&gt; for EfdFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;MemFdCreateFlag&gt; for MemFdCreateFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;ProtFlags&gt; for ProtFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;MapFlags&gt; for MapFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;MsFlags&gt; for MsFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;MlockAllFlags&gt; for MlockAllFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;Options&gt; for Options","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;QuotaValidFlags&gt; for QuotaValidFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;SaFlags&gt; for SaFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;SfdFlags&gt; for SfdFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;SockFlag&gt; for SockFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;MsgFlags&gt; for MsgFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;SFlag&gt; for SFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;Mode&gt; for Mode","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;FsFlags&gt; for FsFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;InputFlags&gt; for InputFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;OutputFlags&gt; for OutputFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;ControlFlags&gt; for ControlFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;LocalFlags&gt; for LocalFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;WaitPidFlag&gt; for WaitPidFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;AddWatchFlags&gt; for AddWatchFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;InitFlags&gt; for InitFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;TimerFlags&gt; for TimerFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;TimerSetTimeFlags&gt; for TimerSetTimeFlags","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;AccessFlags&gt; for AccessFlags","synthetic":false,"types":[]}];
implementors["proc_macro2"] = [{"text":"impl FromIterator&lt;TokenTree&gt; for TokenStream","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;TokenStream&gt; for TokenStream","synthetic":false,"types":[]}];
implementors["rs9p"] = [{"text":"impl FromIterator&lt;LockType&gt; for LockType","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;LockFlag&gt; for LockFlag","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;LockStatus&gt; for LockStatus","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;QidType&gt; for QidType","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;GetattrMask&gt; for GetattrMask","synthetic":false,"types":[]},{"text":"impl FromIterator&lt;SetattrMask&gt; for SetattrMask","synthetic":false,"types":[]}];
implementors["syn"] = [{"text":"impl&lt;T, P&gt; FromIterator&lt;T&gt; for Punctuated&lt;T, P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Default,&nbsp;</span>","synthetic":false,"types":[]},{"text":"impl&lt;T, P&gt; FromIterator&lt;Pair&lt;T, P&gt;&gt; for Punctuated&lt;T, P&gt;","synthetic":false,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()