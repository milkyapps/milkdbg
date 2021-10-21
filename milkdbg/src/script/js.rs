use flume::*;
use log::debug;
use rusty_v8 as v8;
use std::{any::Any, ops::Deref};
use v8::{
    Context, ContextScope, FunctionCallback, Handle, HandleScope, Local, MapFnTo, Object,
    PromiseResolver,
};

use super::Events;
use std::concat_idents;
static mut ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

macro_rules! gen_method {
    ($scope:ident, $global:ident, $s:ident, $name:ident $(,$arg:ident)*) => {
        concat_idents::concat_idents! {fn_name = $name, _callback {
            fn fn_name(
                scope: &mut v8::HandleScope,
                args: v8::FunctionCallbackArguments,
                mut retval: v8::ReturnValue,
            ) {
                let s = unsafe { v8::Local::<v8::External>::cast(args.data().unwrap()) };
                let s = unsafe { &mut *(s.value() as *mut flume::Sender<Events>) };

                let mut vargs = vec![];
                $(
                    let $arg = args.get(vargs.len() as i32).to_rust_string_lossy(scope);
                    vargs.push($arg.into());
                )*

                let resolver = v8::PromiseResolver::new(scope).unwrap();
                let promise = resolver.get_promise(scope);

                let context = scope.get_current_context();
                let global = context.global(scope);

                let id = unsafe { ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst) };
                global.set_index(scope, id, resolver.into()).unwrap();

                let msg = Events::NativeCode(id, stringify!($name).to_string(), vargs);
                debug!("jsevent_to_dbgcmd {:?}", msg);
                s.send(msg);

                retval.set(promise.into());
            }

            {
                let f = new_method(&mut $scope, $s.clone(), fn_name);
                let name = v8::String::new(&mut $scope, stringify!($name)).unwrap();
                $global.set(&mut $scope, name.into(), f.into()).unwrap();
            }
        }}
    };
}

fn call_callback_callback(
    scope: &mut v8::HandleScope,
    args: v8::FunctionCallbackArguments,
    mut retval: v8::ReturnValue,
) {
    let s = unsafe { v8::Local::<v8::External>::cast(args.data().unwrap()) };
    let s = unsafe { &*(s.value() as *mut flume::Sender<()>) }; //todo this is leaking
    s.send(());
}

fn new_method<'a, T, F: MapFnTo<FunctionCallback>>(
    scope: &mut v8::HandleScope<'a>,
    s: flume::Sender<T>,
    callback: F,
) -> Local<'a, v8::Function> {
    let s = Box::leak(Box::new(s));

    let external = v8::External::new(scope, s as *mut Sender<T> as *mut std::ffi::c_void);
    let f = v8::Function::builder(callback)
        .data(external.into())
        .build(scope)
        .unwrap();
    f
}

pub struct JavascriptEngine;

impl JavascriptEngine {
    pub fn spawn(sender: Sender<Events>) -> Sender<super::Commands> {
        let (s, r) = unbounded::<super::Commands>();
        std::thread::spawn(move || {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform);
            v8::V8::initialize();

            let mut isolate = v8::Isolate::new(v8::CreateParams::default());
            let mut handle_scope = v8::HandleScope::new(&mut isolate);

            let s = Box::leak(Box::new(sender));
            let context = v8::Context::new(&mut handle_scope);
            let mut scope = v8::ContextScope::new(&mut handle_scope, context);
            let global = context.global(&mut scope);

            gen_method! {scope, global, s, init, arg0}
            gen_method! {scope, global, s, go}
            gen_method! {scope, global, s, addBreakpoint, arg0}

            let mut i = 0;
            loop {
                let code = r.recv();
                match code {
                    Ok(crate::script::Commands::Resolve(index, value)) => {
                        let result = v8::String::new(&mut scope, value.as_str()).unwrap();

                        let resolver = global.get_index(&mut scope, index).unwrap();
                        let resolver = unsafe { v8::Local::<v8::PromiseResolver>::cast(resolver) };
                        resolver.resolve(&mut scope, result.into());

                        global.delete_index(&mut scope, index);
                    }
                    Ok(crate::script::Commands::Run(code, callback)) => {
                        let code = v8::String::new(&mut scope, &code).unwrap();
                        let script = v8::Script::compile(&mut scope, code, None).unwrap();
                        if let Some(result) = script.run(&mut scope) {
                            if result.is_promise() {
                                let p = unsafe { v8::Local::<v8::Promise>::cast(result) };
                                let fname = format!("f_{}", i);
                                let f = new_method(
                                    &mut scope,
                                    callback.clone(),
                                    call_callback_callback,
                                );
                                p.then(&mut scope, f);
                            } else {
                                callback.send(());
                            }
                        }
                    }
                    _ => todo!(),
                }

                i += 1;
            }
        });

        s
    }
}
