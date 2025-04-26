use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Fields};

#[proc_macro_derive(StructPacker)]
pub fn struct_packer_macro(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let fields = match input.data {
        syn::Data::Struct(s) => match s.fields {
            Fields::Named(fields) => fields.named,
            Fields::Unnamed(fields) => fields.unnamed,
            Fields::Unit => panic!("Unit structs are not supported"),
        },
        _ => panic!("StructPacker can only be derived for structs"),
    };

    let size_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            _size += self.#field_name.size();
        }
    });

    let pack_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            self.#field_name.pack(enc);
        }
    });

    let unpack_fields = fields.iter().map(|f| {
        let field_name = &f.ident;
        quote! {
            dec.unpack(&mut self.#field_name)?;
        }
    });

    let expanded = quote! {
        impl Packer for #name {
            fn size(&self) -> usize {
                let mut _size: usize = 0;
                #(#size_fields)*
                _size
            }

            fn pack(&self, enc: &mut Encoder) -> usize {
                let pos = enc.get_size();
                #(#pack_fields)*
                enc.get_size() - pos
            }

            fn unpack(&mut self, data: &[u8]) -> Result<usize, PackerError> {
                let mut dec = Decoder::new(data);
                #(#unpack_fields)*
                Ok(dec.get_pos())
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(EnumPacker)]
pub fn enum_packer_macro(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let gen = match input.data {
        syn::Data::Enum(data_enum) => {
            let size_variants = data_enum.variants.iter().map(|variant| {
                let variant_ident = &variant.ident;
                match &variant.fields {
                    Fields::Unnamed(fields) => {
                        if fields.unnamed.len() != 1 {
                            panic!("Each variant must have exactly one field implementing the Packer trait.");
                        }
                        quote! {
                            #name::#variant_ident(x) => { _size = 1 + x.size(); }
                        }
                    },
                    _ => panic!("Only unnamed fields are supported"),
                }
            });

            let pack_variants = data_enum.variants.iter().enumerate().map(|(i, variant)| {
                let variant_ident = &variant.ident;
                quote! {
                    #name::#variant_ident(x) => {
                        let mut i: u8 = #i as u8;
                        i.pack(enc);
                        x.pack(enc);
                    }
                }
            });

            let unpack_variants = data_enum.variants.iter().enumerate().map(|(i, variant)| {
                let variant_ident = &variant.ident;
                let variant_type = &variant.fields;
                let variant_default = match variant_type {
                    Fields::Unnamed(fields) => {
                        let ty = &fields.unnamed.first().unwrap().ty;
                        quote! {
                            let mut v: #ty = Default::default();
                            dec.unpack(&mut v)?;
                            *self = #name::#variant_ident(v);
                        }
                    }
                    _ => panic!("Only unnamed fields are supported"),
                };
                quote! {
                    #i => {
                        #variant_default
                    }
                }
            });

            let default_variant = &data_enum.variants[0];
            let default_variant_ident = &default_variant.ident;

            quote! {
                impl Default for #name {
                    #[inline]
                    fn default() -> Self {
                        #name::#default_variant_ident(Default::default())
                    }
                }

                impl ::antelope::serializer::Packer for #name {
                    fn size(&self) -> usize {
                        let mut _size: usize = 0;
                        match self {
                            #( #size_variants ),*
                        }
                        _size
                    }

                    fn pack(&self, enc: &mut ::antelope::serializer::Encoder) -> usize {
                        let pos = enc.get_size();
                        match self {
                            #( #pack_variants ),*
                        }
                        enc.get_size() - pos
                    }

                    fn unpack<'a>(&mut self, data: &'a [u8]) -> Result<usize, ::antelope::serializer::packer::PackerError> {
                        let mut dec = ::antelope::serializer::Decoder::new(data);
                        let mut variant_type_index: u8 = 0;
                        dec.unpack(&mut variant_type_index)?;
                        let variant_type_index = variant_type_index as usize;
                        match variant_type_index {
                            #( #unpack_variants ),*
                            _ => return Err(::antelope::packer_error!("bad variant index: {}", variant_type_index)),
                        }
                        Ok(dec.get_pos())
                    }
                }
            }
        }
        _ => panic!("EnumPacker can only be derived for enums"),
    };

    TokenStream::from(gen)
}

#[proc_macro_derive(StackEnum)]
pub fn stack_enum(input: TokenStream) -> TokenStream {
    let input   = parse_macro_input!(input as DeriveInput);
    let name    = &input.ident;
    let variants = match input.data {
        syn::Data::Enum(ref e) => &e.variants,
        _ => panic!("StackEnum can only be derived for enums"),
    };

    let arms = variants.iter().enumerate().map(|(idx, v)| {
        let ident = &v.ident;
        let field = &v.fields;
        let push = match field {
            Fields::Unnamed(f) if f.unnamed.len() == 1 => quote! { val.push_to_stack(out); },
            _ => panic!("Each variant must have exactly one unnamed field"),
        };
        quote! {
            #name::#ident(val) => {
                out.push(Value::Condition(#idx as isize));
                #push
            }
        }
    });

    TokenStream::from(quote! {
        impl IOStackValue for #name {
            fn push_to_stack(&self, out: &mut Vec<Value>) {
                match self {
                    #( #arms ),*
                }
            }
        }
    })
}

#[proc_macro_derive(StackStruct)]
pub fn stack_struct(input: TokenStream) -> TokenStream {
    let input  = parse_macro_input!(input as DeriveInput);
    let name   = input.ident;
    let fields = match input.data {
        syn::Data::Struct(s) => s.fields,
        _ => panic!("StackStruct can only be derived for structs"),
    };

    let pushes = fields.iter().enumerate().map(|(idx, f)| {
        let access = match &f.ident {
            Some(ident) => quote! { self.#ident },
            None => {
                let index = syn::Index::from(idx);
                quote! { self.#index }
            }
        };
        quote! {
            ::antelope::serializer::vm::isa::IOStackValue::push_to_stack(
                &#access,
                out,
            );
        }
    });

    TokenStream::from(quote! {
        impl ::antelope::serializer::vm::isa::IOStackValue for #name {
            #[allow(unused_imports)]
            fn push_to_stack(&self, out: &mut Vec<::antelope::serializer::vm::isa::Value>) {
                use ::antelope::serializer::vm::isa::IOStackValue as _;  // brings the trait into scope
                #( #pushes )*
            }
        }
    })
}
